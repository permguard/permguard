// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The synchronizing half: apply (the push), pull, checkout, history — the
//! transfer lifecycle of the specification, client side. Objects move
//! incrementally; the checkpoint and the working tree advance only when the
//! whole closure is present and verified. The head is logically atomic.

use std::collections::{BTreeMap, BTreeSet};

use permguard_notp::{
    CommitPushRequest, ExpectedRef, NegotiatePushRequest, ObjectClaim, UploadObjectsRequest,
};
use permguard_objects::digest::Digest;
use permguard_objects::object::{self, Kind, Object, Tree};
use permguard_objects::policy_id::{ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID};

use super::build::os_noise;
use super::{PlanAction, PolicyRecord, Result, Workspace, err};
use crate::engine::remote::Remote;
use crate::engine::verify;
use crate::engine::workspace::config::{self, Checkpoint};
use crate::engine::workspace::inventory;
use crate::engine::workspace::manifest_file;
use permguard_client::Store;
use permguard_client::pull;

/// What an apply reports.
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    /// The ref the apply moved: the one this workspace tracks (BUG-0204).
    pub r#ref: String,
    pub head: String,
    pub counter: u64,
    pub uploaded: usize,
}

/// What a verify reports.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub r#ref: String,
    /// The remote's verified head and counter.
    pub head: String,
    pub counter: u64,
    pub local_closure_objects: Option<usize>,
    /// The head the local closure was walked from, and its counter: the workspace's checkpoint,
    /// which is behind the remote's when the counters differ (BUG-0135).
    pub local_head: Option<String>,
    pub local_counter: Option<u64>,
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
    /// The ref a checkout bound to when it does not exist yet on a ledger whose default ref has
    /// a history: the ledger is not empty, the ref is new (BUG-0204).
    pub missing_ref: Option<String>,
}

/// The request id of a push: the ledger, the ref and the new head name it. A retry of the same
/// apply is the same request; the same commit applied to another ref, or to the same ref of
/// another ledger, is another one (TD-3: two ledgers named alike in two zones, given one commit in
/// one second, collided on one id and the second push was refused as a reused request).
fn push_request_id(ledger: &config::LedgerConfig, r#ref: &str, new_head: &Digest) -> String {
    let named = |id: &str, name: &str| {
        if id.is_empty() {
            name.to_owned()
        } else {
            id.to_owned()
        }
    };
    Digest::compute(
        format!(
            "{zone}/{ledger}\n{ref}\n{new_head}",
            zone = named(&ledger.zone_id, &ledger.zone),
            ledger = named(&ledger.ledger_id, &ledger.ledger),
            ref = r#ref
        )
        .as_bytes(),
    )
    .to_string()
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
                r#ref: r#ref.clone(),
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
        // A retry of an apply whose answer was lost is the same request whenever it comes: the
        // commit it sent is kept until it is answered, and sent again while the tree, the parent,
        // the author and the message are what it carries — a commit stamped anew each second
        // would be another request, and its answer "someone applied before you" (BUG-0136).
        let pending = self.pending_commit(&r#ref)?.filter(|(_, held)| {
            held.tree == snapshot.root
                && held.manifest == snapshot.manifest
                && held.predecessors == expected_old.iter().cloned().collect::<Vec<_>>()
                && held.author == author
                && held.message == message
        });
        let new_head = match pending {
            Some((digest, _)) => digest,
            None => {
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
                self.store
                    .write(
                        &config::pending_path(&r#ref),
                        format!("{new_head}\n").as_bytes(),
                    )
                    .map_err(err)?;
                new_head
            }
        };
        let expected_ref = self.expected_ref(remote, ledger, &r#ref, checkpoint.as_ref())?;
        let request_id = push_request_id(ledger, &r#ref, &new_head);

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
                expected_ref: expected_ref.clone(),
                closure: claims,
                request_id: request_id.clone(),
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
                        transfer_id: negotiated.transfer_id,
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
                    transfer_id: negotiated.transfer_id,
                })
                .map_err(err)?;
        }

        // Finalize ONCE: the compare-and-swap commit.
        let committed = remote
            .commit_push(&CommitPushRequest {
                r#ref: r#ref.clone(),
                new_head: new_head.clone(),
                expected_ref,
                transfer_id: negotiated.transfer_id,
                request_id,
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
        if committed.head != statement.digest
            || committed.counter != statement.counter
            || committed.ref_digest != statement.ref_digest
        {
            return Err(err(
                "the committed ref state is not the one its statement signs",
            ));
        }

        let checkpoint = Checkpoint {
            head: statement.digest.to_string(),
            counter: statement.counter,
            ref_digest: Some(statement.ref_digest.to_string()),
            ..Checkpoint::default()
        };
        config::write_checkpoint(self.store, &r#ref, &checkpoint).map_err(err)?;
        config::write_head(self.store, &r#ref).map_err(err)?;
        // Answered: nothing is pending any more.
        self.store
            .remove(&config::pending_path(&r#ref))
            .map_err(err)?;
        Ok(ApplyOutcome {
            r#ref,
            head: checkpoint.head,
            counter: checkpoint.counter,
            uploaded,
        })
    }

    /// The commit an earlier apply of `ref` sent and saw no answer to, when one is kept and its
    /// object is still in the store.
    fn pending_commit(&self, r#ref: &str) -> Result<Option<(Digest, object::Commit)>> {
        let Some(bytes) = self.store.read(&config::pending_path(r#ref)).map_err(err)? else {
            return Ok(None);
        };
        let Ok(digest) = Digest::parse(String::from_utf8_lossy(&bytes).trim()) else {
            return Ok(None);
        };
        Ok(load_commit(self.store, &digest)
            .ok()
            .map(|commit| (digest, commit)))
    }

    /// The ref state an apply expects to replace: the checkpoint's, `None` before the first
    /// apply. A checkpoint written before the ref digest names no digest: the server's
    /// advertised state, verified against it, names the digest when its head is the one held.
    fn expected_ref(
        &self,
        remote: &dyn Remote,
        ledger: &config::LedgerConfig,
        r#ref: &str,
        checkpoint: Option<&Checkpoint>,
    ) -> Result<Option<ExpectedRef>> {
        let Some(held) = checkpoint else {
            return Ok(None);
        };
        if let Some(digest) = &held.ref_digest {
            return Ok(Some(ExpectedRef {
                counter: held.counter,
                digest: Digest::parse(digest).map_err(|_| err("the checkpoint is corrupt"))?,
            }));
        }
        let answer = remote
            .get_ref(r#ref)
            .map_err(err)?
            .ok_or_else(|| err(format!("the ref `{ref}` is gone from the server", ref = r#ref)))?;
        let jwks = remote.keyring().map_err(err)?;
        let statement = verify::verify_statement(
            &jwks,
            &answer.statement,
            &ledger.zone_id,
            &ledger.ledger_id,
            r#ref,
            Some(held),
        )
        .map_err(err)?;
        if statement.digest.to_string() != held.head || statement.counter != held.counter {
            return Err(err(
                "the ref moved since this workspace last synchronized: pull first",
            ));
        }
        Ok(Some(ExpectedRef {
            counter: statement.counter,
            digest: statement.ref_digest,
        }))
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
            missing_ref: None,
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
        // What a checkout that fails without switching puts back: the binding and the ref it
        // found, so a refused checkout leaves `.permguard/config` as it was (BUG-0111).
        let config_before = config.clone();
        let head_before = config::read_head(self.store).map_err(err)?;
        let current_ref = head_before
            .clone()
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
                    missing_ref: self.missing_ref(remote, r#ref)?,
                });
            }
            let mut outcome = self.pull(remote, false)?;
            removed.append(&mut outcome.removed);
            outcome.removed = removed;

            return Ok(outcome);
        }
        // Nothing was removed, so a checkout that fails from here puts the binding and the ref
        // back as they were, and the workspace is as the author left it (BUG-0111).
        let bound = self.bind_and_pull(remote, r#ref);
        if bound.is_err() {
            let _ = self.save_config(&config_before);
            let _ = match &head_before {
                Some(head) => config::write_head(self.store, head),
                None => self.store.remove(config::HEAD_PATH),
            };
        }
        bound
    }

    /// The pull of a checkout that switched nothing: towards a ledger with no ref yet, an empty
    /// outcome; otherwise the ledger's head, pulled.
    fn bind_and_pull(&self, remote: &dyn Remote, r#ref: &str) -> Result<PullOutcome> {
        // A ledger with no ref yet is not an error to bind to: the first apply will create it. The
        // binding stays; there is nothing to pull. Asked of the remote, as a switch asks it, rather
        // than read from the wording of a failed pull, which every server words its own way.
        let missing_ref = self.missing_ref(remote, r#ref)?;
        let empty = || PullOutcome {
            head: String::new(),
            counter: 0,
            fetched: 0,
            materialized: Vec::new(),
            updated: Vec::new(),
            removed: Vec::new(),
            previous_counter: None,
            missing_ref: missing_ref.clone(),
        };
        if remote.get_ref(r#ref).map_err(err)?.is_none() {
            return Ok(empty());
        }
        match self.pull(remote, false) {
            Ok(outcome) => Ok(outcome),
            // The ref went between the question and the pull.
            Err(error)
                if error.message.contains("not_found") || error.message.contains("no ref") =>
            {
                Ok(empty())
            }
            Err(error) => Err(error),
        }
    }

    /// `r#ref` when it is not the default ref and the default ref has a history: a checkout
    /// bound to a ref that does not exist yet on a ledger that is not empty (BUG-0204).
    fn missing_ref(&self, remote: &dyn Remote, r#ref: &str) -> Result<Option<String>> {
        if r#ref == super::DEFAULT_REF {
            return Ok(None);
        }
        Ok(remote
            .get_ref(super::DEFAULT_REF)
            .map_err(err)?
            .map(|_| r#ref.to_owned()))
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
        let Some(answer) = remote.get_ref(&r#ref).map_err(err)? else {
            return Err(err(missing_ref_or_ledger(remote, ledger, &r#ref)));
        };
        let jwks = remote.keyring().map_err(err)?;
        let statement = verify::verify_statement(
            &jwks,
            &answer.statement,
            &ledger.zone_id,
            &ledger.ledger_id,
            &r#ref,
            checkpoint.as_ref(),
        )
        .map_err(super::unverified)?;
        let local_head = checkpoint.as_ref().map(|held| held.head.clone());
        let local_counter = checkpoint.as_ref().map(|held| held.counter);
        let local_closure_objects = match checkpoint {
            Some(checkpoint) => {
                let head =
                    Digest::parse(&checkpoint.head).map_err(|_| err("corrupt checkpoint"))?;
                // A local closure that does not hash to what the checkpoint says did not pass.
                Some(
                    walk_local(self.store, &head)
                        .map_err(|error| super::unverified(error.message))?
                        .len(),
                )
            }
            None => None,
        };
        Ok(VerifyOutcome {
            r#ref: r#ref.clone(),
            head: statement.digest.to_string(),
            counter: statement.counter,
            local_closure_objects,
            local_head,
            local_counter,
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
        // A partition the ledger dropped leaves no folder behind once its files went: an
        // undeclared folder would be dirt the pull made itself. One still holding something the
        // author keeps stays, and the build names it.
        for partition in &plan.dropped_partitions {
            remove_if_empty(self.store, partition)?;
        }
        Ok(plan)
    }

    /// Decides what the incoming head does to the working tree, without
    /// touching it — so a conflict costs nothing and leaves nothing behind.
    fn plan_materialization(&self, head: &Digest) -> Result<Materialization> {
        let commit = load_commit(self.store, head)?;
        let incoming = head_contents(self.store, head)?;
        let tracked = tracked_head(self.store)?;
        let mut plan = Materialization::default();

        // The manifest is merged three ways like every other file (DEC-0003, BUG-0017): unchanged
        // here since the checkpoint, it takes the incoming one; changed here and unchanged there,
        // it stays the author's, which `apply` sends; changed on both sides, the pull refuses and
        // names it. Before the first checkpoint there is no base, and a manifest in the tree is
        // the author's, checked against what lands below.
        let local_manifest = manifest_file::find(self.store).map_err(err)?;
        let mut adopting = false;
        if let (Some(file), Some(previous)) = (local_manifest, &tracked) {
            let ours = manifest_file::load(self.store)
                .map_err(err)?
                .encode()
                .map_err(|error| err(error.to_string()))?;
            let base = load_blob_data(self.store, &load_commit(self.store, previous)?.manifest)?;
            let theirs = load_blob_data(self.store, &commit.manifest)?;
            if ours != theirs && base != theirs {
                if ours == base {
                    let manifest = permguard_objects::manifest::Manifest::decode(&theirs)
                        .map_err(|error| err(error.to_string()))?;
                    plan.updates.push((
                        file.to_owned(),
                        manifest_file::to_yaml(&manifest).map_err(err)?.into_bytes(),
                    ));
                    let previous = permguard_objects::manifest::Manifest::decode(&base)
                        .map_err(|error| err(error.to_string()))?;
                    plan.dropped_partitions = previous
                        .partitions
                        .keys()
                        .filter(|name| !manifest.partitions.contains_key(*name))
                        .cloned()
                        .collect();
                    adopting = true;
                } else {
                    plan.conflicts.push(Conflict {
                        path: file.to_owned(),
                        reason: Reason::BothChanged {
                            incoming: commit.manifest.clone(),
                        },
                    });
                }
            }
        }

        // A manifest already in the tree is the author's, and it says which partitions the tree
        // has. A head carrying a partition the manifest does not declare cannot land on it: the
        // files would be written where no build reads them, and the next `plan` — the tracked
        // head against a tree that never declared them — would delete them from the ledger.
        // Refused before a byte is written, naming the partition and both ways out.
        if local_manifest.is_some() && !adopting {
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
            // Absent here and in the base: the author deleted it, and that deletion is what
            // `apply` sends — unless the remote changed it since, which only the author can weigh
            // (DEC-0003, BUG-0026). Never written back.
            if !local.contains_key(id)
                && let Some((based, _)) = base.policies.get(id)
            {
                if based != digest {
                    plan.conflicts.push(Conflict {
                        path: canonical.clone(),
                        reason: Reason::DeletedHere {
                            incoming: digest.clone(),
                        },
                    });
                }
                continue;
            }
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
                    // A file ends with a newline: the build trims it from the policy's bytes,
                    // so the file round-trips as its author wrote it (BUG-0298).
                    let mut written = load_blob_data(self.store, digest)?;
                    if !written.is_empty() && !written.ends_with(b"\n") {
                        written.push(b'\n');
                    }
                    plan.creates.push((canonical.clone(), written));
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
        for (id, (digest, canonical)) in &base.policies {
            if incoming.policies.contains_key(id) {
                continue;
            }
            let Some(held) = local.get(id) else {
                // An un-aliased policy is named by its text: edited here, the file the base held
                // it in now holds a policy neither side had. Dropped there, the remote replaced or
                // removed it: both sides changed it, and the remote's version is never written
                // beside this one unasked (BUG-0233).
                if let Some(edited) = local.values().find(|held| {
                    &held.source == canonical
                        && !base.policies.contains_key(&held.id)
                        && !incoming.policies.contains_key(&held.id)
                }) && !plan
                    .conflicts
                    .iter()
                    .any(|conflict| conflict.path == edited.source)
                {
                    plan.conflicts.push(Conflict {
                        path: edited.source.clone(),
                        reason: Reason::ReplacedBoth,
                    });
                }
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
        // The file is compared as the build reads it, its CRLF made LF (BUG-0238), and an update
        // is written in the file's own line endings.
        for (path, digest) in &incoming.others {
            let theirs = load_blob_data(self.store, digest)?;
            let Some(raw) = self.store.read(path).map_err(err)? else {
                // Deleted here since the checkpoint: a pending deletion, or a conflict when the
                // remote changed it (DEC-0003).
                match base.others.get(path) {
                    Some(based) if based == digest => {}
                    Some(_) => plan.conflicts.push(Conflict {
                        path: path.clone(),
                        reason: Reason::DeletedHere {
                            incoming: digest.clone(),
                        },
                    }),
                    None => plan.creates.push((path.clone(), theirs)),
                }
                continue;
            };
            let crlf = has_crlf(&raw);
            let ours = super::build::authored(raw);
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
                plan.updates
                    .push((path.clone(), if crlf { to_crlf(&theirs) } else { theirs }));
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
            if super::build::authored(ours) == load_blob_data(self.store, digest)? {
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

/// Why a ref read answered nothing: the ref is missing on the ledger this workspace tracks, or the
/// ledger itself is gone (BUG-0006). A ref read answers "not found" for both, so the ledger is
/// looked up by the names it was checked out under, and its id, the identity (DEC-0005), says
/// which: none answers, another ledger answers, or the tracked one does and the ref is missing.
fn missing_ref_or_ledger(
    remote: &dyn Remote,
    ledger: &config::LedgerConfig,
    r#ref: &str,
) -> String {
    let tracked = format!("{}/{}", ledger.zone, ledger.ledger);
    match remote.resolve(&ledger.zone, &ledger.ledger) {
        Ok((_, found)) if ledger.ledger_id.is_empty() || found == ledger.ledger_id => {
            format!("the remote has no ref `{ref}` on `{tracked}`", ref = r#ref)
        }
        Ok((_, found)) => format!(
            "the ledger this workspace tracks (`{tracked}`, id {}) no longer exists on the \
             remote: `{tracked}` now names another ledger (id {found}). Check out the ledger to \
             work on",
            ledger.ledger_id
        ),
        Err(answer) => format!(
            "the ledger this workspace tracks (`{tracked}`, id {}) does not exist on the remote \
             ({answer}): it was deleted or renamed. Check out the ledger to work on",
            ledger.ledger_id
        ),
    }
}

/// Removes `path` when it holds nothing but folders and OS noise; answers whether it went.
fn remove_if_empty(store: &dyn Store, path: &str) -> Result<bool> {
    let mut empty = true;
    for (name, is_dir) in store.list(path).map_err(err)? {
        let child = format!("{path}/{name}");
        if is_dir {
            empty &= remove_if_empty(store, &child)?;
        } else if !os_noise(&name) {
            empty = false;
        }
    }
    if empty && store.links(path).map_err(err)?.is_empty() {
        store.remove(path).map_err(err)?;
    }
    Ok(empty)
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
        // What the operating system dropped goes with the folder: keeping a partition alive for
        // a `.DS_Store` would leave a folder the new manifest does not declare — dirt, by the
        // build's own rule, made by the checkout itself.
        if !(os_noise(&name) && !is_dir) && super::build::ignored(ignores, &child, is_dir) {
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
    /// Partitions the incoming manifest no longer declares, whose folders go once empty.
    dropped_partitions: Vec<String>,
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
                Reason::ReplacedBoth => message.push_str(&format!(
                    "\n  - {path}: changed here and on the remote, which replaced the policy this \
                     file held — an un-aliased policy is named by its text, so the two versions \
                     cannot be paired: `permguard pull --resolved` writes the remote's version \
                     beside this file; fold your change into it and delete this file, or give the \
                     policy an `@alias`"
                )),
                Reason::DroppedThere => message.push_str(&format!(
                    "\n  - {path}: the remote dropped it and this workspace changed it — delete \
                     the file to accept the removal, or apply it back"
                )),
                Reason::DeletedHere { incoming } => message.push_str(&format!(
                    "\n  - {path}: deleted here and changed on the remote — restore it from \
                     `permguard objects cat {incoming}` to keep the change, or keep it deleted \
                     and pull with --resolved"
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
    /// An un-aliased policy this workspace edited, which the remote replaced or removed: its id is
    /// its text, so the two sides hold different ids for what was one policy (BUG-0233).
    ReplacedBoth,
    /// This workspace deleted it, and the remote changed it.
    DeletedHere { incoming: Digest },
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
    // A blob is the authored text, LF; a file a Windows checkout wrote is CRLF. The policy is
    // found, and its new text written, in the file's own line endings (BUG-0238).
    let crlf = has_crlf(content);
    let (old, new) = if crlf {
        (to_crlf(old), new.map(to_crlf))
    } else {
        (old.to_vec(), new.map(<[u8]>::to_vec))
    };
    let (old, new) = (old.as_slice(), new.as_deref());
    let separator: &[u8] = if crlf { b"\r\n\r\n" } else { b"\n\n" };
    let ending: &[u8] = if crlf { b"\r\n" } else { b"\n" };
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
                (false, true) => [before, ending].concat(),
                (false, false) => [before, separator, after].concat(),
            }
        }
    })
}

/// Whether a file's lines end in CRLF, as a Windows checkout writes them.
fn has_crlf(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|pair| pair == b"\r\n")
}

/// `bytes` with every LF made CRLF; an LF already after a CR is left as it is.
fn to_crlf(bytes: &[u8]) -> Vec<u8> {
    let mut written = Vec::with_capacity(bytes.len() + bytes.len() / 16);
    for (at, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' && (at == 0 || bytes[at - 1] != b'\r') {
            written.push(b'\r');
        }
        written.push(*byte);
    }
    written
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

/// The non-policy blobs of the tracked head — schemas and other artifacts — by the path they land
/// at; none before the first checkpoint.
pub(crate) fn tracked_others(store: &dyn Store) -> Result<BTreeMap<String, Digest>> {
    match tracked_head(store)? {
        Some(head) => Ok(head_contents(store, &head)?.others),
        None => Ok(BTreeMap::new()),
    }
}

/// The non-policy blobs of a snapshot, read from its own objects, by the path they land at: what
/// [`tracked_others`] answers for the head, so the two compare path by path.
pub(crate) fn snapshot_others(snapshot: &super::Snapshot) -> BTreeMap<String, Digest> {
    fn tree_of(
        snapshot: &super::Snapshot,
        digest: &Digest,
    ) -> Option<permguard_objects::object::Tree> {
        match permguard_objects::object::decode(snapshot.objects.get(digest)?) {
            Ok(Object::Tree(tree)) => Some(tree),
            _ => None,
        }
    }
    fn walk(
        snapshot: &super::Snapshot,
        directory: &str,
        digest: &Digest,
        others: &mut BTreeMap<String, Digest>,
    ) {
        let Some(tree) = tree_of(snapshot, digest) else {
            return;
        };
        for item in tree.entries {
            let path = format!("{directory}/{}", item.name);
            match item.kind {
                Kind::Tree => walk(snapshot, &path, &item.digest, others),
                Kind::Blob if !item.annotations.contains_key(ANNOTATION_POLICY_ID) => {
                    others.insert(path, item.digest);
                }
                _ => {}
            }
        }
    }
    let mut others = BTreeMap::new();
    if let Some(root) = tree_of(snapshot, &snapshot.root) {
        for entry in root.entries {
            if entry.kind == Kind::Tree {
                walk(snapshot, &entry.name, &entry.digest, &mut others);
            }
        }
    }
    others
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

/// What the tracked head *is*, beyond its policies and artifacts: its manifest, which a plan
/// compares as it compares every file (DEC-0003). A plan that compared only policies would call a
/// changed manifest "no changes", which is exactly the bug this exists to make impossible.
#[derive(Debug, Clone)]
pub(crate) struct TrackedShape {
    pub manifest: Digest,
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

    Ok(Some(TrackedShape {
        manifest: commit.manifest,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(zone: &str, ledger: &str) -> config::LedgerConfig {
        config::LedgerConfig {
            remote: "origin".to_owned(),
            zone: zone.to_owned(),
            ledger: "main".to_owned(),
            zone_id: format!("{zone}-id"),
            ledger_id: ledger.to_owned(),
        }
    }

    /// TD-3: one commit pushed to the same ref of two ledgers is two requests; a retry of one
    /// push is the same request.
    #[test]
    fn a_push_is_named_by_its_ledger_its_ref_and_its_head() {
        let head = Digest::compute(b"one commit");
        let acme = push_request_id(&tracked("acme", "l1"), "main", &head);
        assert_eq!(acme, push_request_id(&tracked("acme", "l1"), "main", &head));
        assert_ne!(acme, push_request_id(&tracked("beta", "l1"), "main", &head));
        assert_ne!(acme, push_request_id(&tracked("acme", "l2"), "main", &head));
        assert_ne!(
            acme,
            push_request_id(&tracked("acme", "l1"), "other", &head)
        );
        assert_ne!(
            acme,
            push_request_id(&tracked("acme", "l1"), "main", &Digest::compute(b"another"))
        );
        // Before checkout resolved the ids, the names stand for them.
        let unresolved = config::LedgerConfig {
            zone_id: String::new(),
            ledger_id: String::new(),
            ..tracked("acme", "l1")
        };
        assert_ne!(
            push_request_id(&unresolved, "main", &head),
            push_request_id(
                &config::LedgerConfig {
                    zone: "beta".to_owned(),
                    ..unresolved.clone()
                },
                "main",
                &head
            )
        );
    }
}
