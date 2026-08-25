// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The server side of NOTP: negotiation, ingest, and the commit acceptance
//! invariants — every check the specification lists, run in full on what is
//! actually on disk, fail-closed. Transports call this and shape answers;
//! nothing here knows HTTP or gRPC.

use std::collections::{BTreeMap, BTreeSet};

use crate::store::{FileObjectStore, RefState, RefUpdate, StoreError};
use permguard_notp::*;
use permguard_objects::digest::Digest;
use permguard_objects::grammar;
use permguard_objects::limits;
use permguard_objects::object::{self, Commit, Kind, Object, Tree};
use permguard_objects::policy_id::{self, ResolvedId};
use permguard_objects::statement::HeadStatement;

use permguard_languages::registry;
pub use permguard_languages::registry::{
    ENGINE_NAME, ENGINE_VERSION, MEDIA_TYPE_MANIFEST, MEDIA_TYPE_POLICY_CEDAR,
    MEDIA_TYPE_POLICY_REGO, MEDIA_TYPE_SCHEMA_CEDAR, provided_runtimes,
};
use permguard_objects::policy_id::POLICY_FAMILY_PREFIX;
pub use permguard_objects::policy_id::{
    ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND,
};

/// The well-known root entry holding the manifest.
const MANIFEST_ENTRY: &str = "manifest";

/// A hard stop on history walks, far above any real ledger: a corrupted
/// predecessor loop must terminate, not spin.
const MAX_HISTORY_WALK: usize = 1_000_000;

/// The aggregate bounds one deployment enforces — configuration, not model.
#[derive(Debug, Clone, Copy)]
pub struct EngineLimits {
    /// Advertised in every negotiate response, per transport.
    pub max_batch_bytes: u64,
    pub max_batch_objects: u64,
    /// The caps of one push delta, preflight at negotiate and re-enforced at commit.
    pub max_push_objects: u64,
    pub max_push_bytes: u64,
    /// The storage quota of one ledger, checked atomically at upload.
    pub ledger_quota_bytes: u64,
}

/// The identity of the ledger being served, for the signed statement.
#[derive(Debug, Clone)]
pub struct LedgerIdentity {
    pub zone_id: String,
    pub ledger_id: String,
}

/// Signs head statements: given the statement, returns the COSE envelope.
/// The engine never holds a key; the composition root decides what signs.
pub type HeadSigner<'a> = &'a dyn Fn(&HeadStatement) -> std::result::Result<Vec<u8>, EngineError>;

/// Why the engine refused — the vocabulary transports map onto the taxonomy.
#[derive(Debug)]
pub enum EngineError {
    /// The request breaks a rule of the model or the protocol.
    Validation { code: &'static str, message: String },
    /// The ref moved, or a creation raced: carries what is current.
    Conflict { current: Option<RefState> },
    /// Nothing answers: an absent ref, an absent object.
    NotFound { what: String },
    /// A quota refused the work.
    Unavailable { message: String },
    /// The store or the signer failed.
    Internal { detail: String },
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Validation { code, message } => write!(f, "{code}: {message}"),
            EngineError::Conflict { .. } => write!(f, "the ref moved: compare-and-swap conflict"),
            EngineError::NotFound { what } => write!(f, "not found: {what}"),
            EngineError::Unavailable { message } => write!(f, "refused by quota: {message}"),
            EngineError::Internal { detail } => write!(f, "internal: {detail}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<StoreError> for EngineError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Conflict { current } => EngineError::Conflict { current },
            StoreError::Object(e) => EngineError::Validation {
                code: "object_rejected",
                message: e.to_string(),
            },
            StoreError::Grammar(e) => EngineError::Validation {
                code: "grammar",
                message: e.to_string(),
            },
            StoreError::Corrupt { digest } => EngineError::Internal {
                detail: format!("stored object {digest} is corrupt"),
            },
            StoreError::Incompatible { found } => EngineError::Internal {
                detail: format!("the store layout is `{found}`; this build speaks another"),
            },
            StoreError::Backend { detail } => EngineError::Internal { detail },
        }
    }
}

fn invalid(code: &'static str, message: impl Into<String>) -> EngineError {
    EngineError::Validation {
        code,
        message: message.into(),
    }
}

type Result<T> = std::result::Result<T, EngineError>;

/// Validate one blob at ingest — the model rule, mapped onto the engine's
/// error vocabulary.
pub fn validate_blob(media_type: &str, data: &[u8]) -> Result<()> {
    registry::validate_blob(media_type, data).map_err(|refused| EngineError::Validation {
        code: refused.code,
        message: refused.message,
    })
}

/// The alias a policy source declares — see [`registry::declared_alias`].
pub fn declared_alias(media_type: &str, source: &[u8]) -> Option<String> {
    registry::declared_alias(media_type, source)
}

/// The NOTP engine over one ledger's store.
pub struct Engine<'a> {
    pub store: &'a FileObjectStore,
    pub identity: LedgerIdentity,
    pub limits: EngineLimits,
}

/// What one partition's walk gathers for the set-level semantic check: every
/// policy's verbatim bytes and every schema's, each named by its entry path so
/// a refusal can cite the file the author will look for.
#[derive(Default)]
struct PartitionSources {
    policies: Vec<(String, Vec<u8>)>,
    schemas: Vec<(String, Vec<u8>)>,
}

impl Engine<'_> {
    // ---- negotiation ----

    /// Push negotiation: preflight the declared delta, answer what is missing.
    pub fn negotiate_push(&self, request: &NegotiatePushRequest) -> Result<NegotiatePushResponse> {
        grammar::validate_ref_name(&request.r#ref)
            .map_err(|e| invalid("grammar", e.to_string()))?;
        if request.closure.len() as u64 > self.limits.max_push_objects {
            return Err(EngineError::Unavailable {
                message: format!(
                    "the push declares more than {} objects",
                    self.limits.max_push_objects
                ),
            });
        }
        let declared_bytes: u64 = request.closure.iter().map(|c| c.size).sum();
        if declared_bytes > self.limits.max_push_bytes {
            return Err(EngineError::Unavailable {
                message: format!(
                    "the push declares more than {} bytes",
                    self.limits.max_push_bytes
                ),
            });
        }
        let missing = request
            .closure
            .iter()
            .filter(|claim| !self.store.has_object(&claim.digest))
            .map(|claim| claim.digest.clone())
            .collect();
        // Raw at this layer: the transport facade stamps the negotiated
        // compression, the engine only ever sees canonical bytes.
        Ok(NegotiatePushResponse {
            missing,
            max_batch_bytes: self.limits.max_batch_bytes,
            max_batch_objects: self.limits.max_batch_objects,
            compression: None,
        })
    }

    /// Ingest one batch: canonical, within limits, media types validated,
    /// idempotent — and inside the ledger quota, checked before writing.
    pub fn upload(&self, request: &UploadObjectsRequest) -> Result<UploadObjectsResponse> {
        if request.objects.len() as u64 > self.limits.max_batch_objects {
            return Err(invalid(
                "batch_rejected",
                "more objects than the advertised batch limit",
            ));
        }
        let batch_bytes: u64 = request.objects.iter().map(|o| o.len() as u64).sum();
        if batch_bytes > self.limits.max_batch_bytes {
            return Err(invalid(
                "batch_rejected",
                "more bytes than the advertised batch limit",
            ));
        }
        let used = self.ledger_bytes()?;
        if used.saturating_add(batch_bytes) > self.limits.ledger_quota_bytes {
            return Err(EngineError::Unavailable {
                message: "the ledger storage quota is exhausted".to_string(),
            });
        }
        let mut received = Vec::with_capacity(request.objects.len());
        for bytes in &request.objects {
            let (digest, decoded) = self.store.put_object(bytes)?;
            if let Object::Blob(blob) = &decoded {
                validate_blob(&blob.media_type, &blob.data)?;
            }
            received.push(digest);
        }
        Ok(UploadObjectsResponse { received })
    }

    // ---- commit ----

    /// The commit: every acceptance invariant, re-run on what is actually on
    /// disk, then the idempotent CAS, then the signed statement.
    pub fn commit_push(
        &self,
        request: &CommitPushRequest,
        signer: HeadSigner<'_>,
    ) -> Result<CommitPushResponse> {
        grammar::validate_ref_name(&request.r#ref)
            .map_err(|e| invalid("grammar", e.to_string()))?;

        // Idempotency first: a retry whose commit already landed is a
        // success and re-runs nothing.
        if let Some(current) = self.store.read_ref(&request.r#ref)?
            && current.head == request.new_head
        {
            return self.answer_with_statement(&request.r#ref, current);
        }

        let old_reachable = match &request.expected_old {
            Some(old) => Some(self.reachable_from(old)?),
            None => None,
        };

        // Branch creation: expected_old absent, but the head already exists
        // and is reachable from an existing ref — nothing new to validate.
        let is_branch = request.expected_old.is_none()
            && self.store.has_object(&request.new_head)
            && self.reachable_from_any_ref(&request.new_head)?;

        if !is_branch {
            self.check_acceptance_invariants(
                &request.new_head,
                request.expected_old.as_ref(),
                old_reachable.as_ref(),
            )?;
        }

        let updated = self.store.update_ref(
            &request.r#ref,
            request.expected_old.as_ref(),
            &request.new_head,
        )?;
        let state = match updated {
            RefUpdate::Updated(state) | RefUpdate::AlreadyCurrent(state) => state,
        };
        let response = self.sign_and_cache(&request.r#ref, &state, signer)?;
        Ok(response)
    }

    // ---- pull ----

    /// Pull negotiation: the head (or a pinned commit reachable from it),
    /// the signed statement, and the delta past the client's checkpoints.
    pub fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
        signer: HeadSigner<'_>,
    ) -> Result<NegotiatePullResponse> {
        grammar::validate_ref_name(&request.r#ref)
            .map_err(|e| invalid("grammar", e.to_string()))?;
        let state = self
            .store
            .read_ref(&request.r#ref)?
            .ok_or_else(|| EngineError::NotFound {
                what: format!("ref `{}`", request.r#ref),
            })?;

        let head_reachable = self.reachable_from(&state.head)?;
        let target = match &request.at {
            Some(at) => {
                if !head_reachable.contains(at) {
                    return Err(invalid(
                        "not_reachable",
                        format!("`{at}` is not reachable from `{}`", request.r#ref),
                    ));
                }
                at.clone()
            }
            None => state.head.clone(),
        };

        // Everything behind a `have` checkpoint stays home.
        let mut haved: BTreeSet<Digest> = BTreeSet::new();
        for have in &request.have {
            if self.store.has_object(have) {
                haved.extend(self.reachable_from(have)?);
            }
        }
        let missing = self
            .walk_region(&target, &haved)?
            .into_iter()
            .collect::<Vec<_>>();

        let statement = self.current_statement(&request.r#ref, &state, signer)?;
        Ok(NegotiatePullResponse {
            head: state.head,
            counter: state.counter,
            statement,
            missing,
            max_batch_bytes: self.limits.max_batch_bytes,
            max_batch_objects: self.limits.max_batch_objects,
            compression: None,
        })
    }

    /// Serve objects, hash-verified on the way out.
    pub fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse> {
        if request.digests.len() as u64 > self.limits.max_batch_objects {
            return Err(invalid(
                "batch_rejected",
                "more objects than the advertised batch limit",
            ));
        }
        let mut objects = Vec::with_capacity(request.digests.len());
        for digest in &request.digests {
            let bytes = self
                .store
                .get_object(digest)?
                .ok_or_else(|| EngineError::NotFound {
                    what: format!("object {digest}"),
                })?;
            objects.push(bytes);
        }
        Ok(FetchObjectsResponse {
            objects,
            compression: None,
        })
    }

    /// The advertised ref: state plus current statement.
    pub fn get_ref(&self, name: &str, signer: HeadSigner<'_>) -> Result<(RefState, Vec<u8>)> {
        grammar::validate_ref_name(name).map_err(|e| invalid("grammar", e.to_string()))?;
        let state = self
            .store
            .read_ref(name)?
            .ok_or_else(|| EngineError::NotFound {
                what: format!("ref `{name}`"),
            })?;
        let statement = self.current_statement(name, &state, signer)?;
        Ok((state, statement))
    }

    // ---- invariants ----

    fn check_acceptance_invariants(
        &self,
        new_head: &Digest,
        expected_old: Option<&Digest>,
        old_reachable: Option<&BTreeSet<Digest>>,
    ) -> Result<()> {
        // The new region: reachable from the new head, minus the old closure.
        let empty = BTreeSet::new();
        let stop = old_reachable.unwrap_or(&empty);
        let region = self.walk_region(new_head, stop)?;

        let mut total_bytes: u64 = 0;
        let mut decoded: BTreeMap<Digest, Object> = BTreeMap::new();
        for digest in &region {
            let bytes = self
                .store
                .get_object(digest)?
                .ok_or_else(|| EngineError::NotFound {
                    what: format!("object {digest}"),
                })?;
            total_bytes += bytes.len() as u64;
            let object = object::decode(&bytes)
                .map_err(|e| invalid("object_rejected", format!("{digest}: {e}")))?;
            decoded.insert(digest.clone(), object);
        }

        // Re-enforced at commit, on actual state: the push delta caps.
        if region.len() as u64 > self.limits.max_push_objects
            || total_bytes > self.limits.max_push_bytes
        {
            return Err(EngineError::Unavailable {
                message: "the push exceeds the delta caps".to_string(),
            });
        }

        let head_commit = match decoded.get(new_head) {
            Some(Object::Commit(commit)) => commit.clone(),
            Some(_) => return Err(invalid("commit_rejected", "the new head is not a commit")),
            None => {
                return Err(EngineError::NotFound {
                    what: format!("commit {new_head}"),
                });
            }
        };

        // Fast-forward: the expected old head must be an ancestor of the new
        // head; `[]` predecessors are legal only for a history root.
        match expected_old {
            Some(old) => {
                if !self.is_ancestor(old, new_head)? {
                    return Err(invalid(
                        "not_fast_forward",
                        format!("`{old}` is not an ancestor of `{new_head}`"),
                    ));
                }
            }
            None => {
                if !head_commit.predecessors.is_empty() {
                    return Err(invalid(
                        "not_a_root",
                        "a push creating a ref must carry a history root or branch an existing commit",
                    ));
                }
            }
        }

        // Kind checks and tree structure, across the region.
        for (digest, object) in &decoded {
            if let Object::Tree(tree) = object {
                for entry in &tree.entries {
                    let actual = self.kind_of(&entry.digest, &decoded)?;
                    if actual != entry.kind {
                        return Err(invalid(
                            "kind_mismatch",
                            format!(
                                "entry `{}` of tree {digest} declares the wrong kind",
                                entry.name
                            ),
                        ));
                    }
                }
            }
        }

        // The manifest invariants and the partition + identity rules run on
        // the new snapshot, whether or not its trees are new objects.
        self.check_snapshot(&head_commit, expected_old)?;

        // Every commit in the region within predecessor rules is already
        // enforced by decoding; depth of trees is enforced by walk_region.
        Ok(())
    }

    /// Validate the head commit's snapshot: manifest authority, partitions,
    /// and policy identity against the previous tree(s).
    fn check_snapshot(&self, head: &Commit, expected_old: Option<&Digest>) -> Result<()> {
        let root = self.load_tree(&head.tree)?;

        // Commit.manifest must equal the digest of the root entry `manifest`,
        // and that blob must be a manifest.
        let manifest_entry = root
            .entries
            .iter()
            .find(|entry| entry.name == MANIFEST_ENTRY && entry.kind == Kind::Blob)
            .ok_or_else(|| invalid("manifest_missing", "the root tree has no `manifest` entry"))?;
        if manifest_entry.digest != head.manifest {
            return Err(invalid(
                "manifest_mismatch",
                "the commit's manifest digest differs from the root entry `manifest`",
            ));
        }
        let manifest_blob = self.load_blob(&head.manifest)?;
        if manifest_blob.media_type != MEDIA_TYPE_MANIFEST {
            return Err(invalid(
                "manifest_rejected",
                "the manifest entry is not a manifest blob",
            ));
        }
        let manifest = permguard_objects::manifest::Manifest::decode(&manifest_blob.data)
            .map_err(|e| invalid("manifest_rejected", e.to_string()))?;

        // The load gate, server side: this build's engine and plugins must
        // satisfy every runtime the manifest declares — fail-closed, or an
        // engine outside the range would validate policies it may misread.
        permguard_objects::manifest::check_load_gate(&manifest, &provided_runtimes())
            .map_err(|e| invalid("runtime_gate", e.to_string()))?;

        // Kind discipline: a policy ledger allows only media types owned by
        // its partitions' language plugins — one kind per ledger, never
        // mixed; and every partition's media types must belong to the
        // language its runtime names (schema types only where schema: true).
        for (name, partition) in &manifest.partitions {
            let runtime = manifest.runtimes.get(&partition.runtime).ok_or_else(|| {
                invalid(
                    "manifest_rejected",
                    format!("partition `{name}` names an undeclared runtime"),
                )
            })?;
            let plugin =
                permguard_languages::language(&runtime.language.name).ok_or_else(|| {
                    invalid(
                        "runtime_gate",
                        format!(
                            "no built-in plugin for the language `{}`",
                            runtime.language.name
                        ),
                    )
                })?;
            if partition.schema && plugin.schema_media_type().is_none() {
                return Err(invalid(
                    "manifest_rejected",
                    format!(
                        "partition `{name}` declares schema: true, but the language `{}` has no schema",
                        runtime.language.name
                    ),
                ));
            }
            for media_type in &partition.media_types {
                let is_policy = plugin.policy_media_type() == media_type;
                let is_schema = plugin.schema_media_type() == Some(media_type.as_str());
                if !is_policy && !is_schema {
                    return Err(invalid(
                        "media_type_not_allowed",
                        format!(
                            "partition `{name}` allows `{media_type}`, which does not belong to the language `{}`",
                            runtime.language.name
                        ),
                    ));
                }
                if is_schema && !partition.schema {
                    return Err(invalid(
                        "manifest_rejected",
                        format!(
                            "partition `{name}` allows a schema media type but declares schema: false"
                        ),
                    ));
                }
            }
        }

        // Partitions and root subtrees must match 1:1 — declared-but-absent
        // rejects here; present-but-undeclared rejects in the walk below.
        for name in manifest.partitions.keys() {
            let present = root
                .entries
                .iter()
                .any(|entry| entry.kind == Kind::Tree && entry.name == *name);
            if !present {
                return Err(invalid(
                    "partition_missing",
                    format!("the manifest declares the partition `{name}`, which has no subtree"),
                ));
            }
        }

        // Previous root tree(s), for the identity cascade — plus, per parent,
        // the alias → id map of the WHOLE snapshot, so a rename that moves an
        // entry across subtrees still finds its identity by alias.
        let previous_roots: Vec<Tree> = match expected_old {
            Some(old) => {
                let commit = self.load_commit(old)?;
                vec![self.load_tree(&commit.tree)?]
            }
            None => Vec::new(),
        };
        let previous_alias_maps: Vec<BTreeMap<String, String>> = previous_roots
            .iter()
            .map(|tree| {
                let mut map = BTreeMap::new();
                self.collect_aliases(tree, &mut map)?;
                Ok(map)
            })
            .collect::<Result<_>>()?;

        // Partitions: every root subtree must be declared; every blob inside
        // must carry an allowed media type; policies must carry their ids.
        let mut all_policy_ids: Vec<String> = Vec::new();
        let mut all_policy_aliases: Vec<String> = Vec::new();
        for entry in &root.entries {
            match entry.kind {
                Kind::Blob => {
                    if entry.name != MANIFEST_ENTRY {
                        return Err(invalid(
                            "partition_rejected",
                            format!(
                                "the root entry `{}` is neither a partition nor the manifest",
                                entry.name
                            ),
                        ));
                    }
                }
                Kind::Tree => {
                    let declared = manifest.partitions.get(&entry.name).ok_or_else(|| {
                        invalid(
                            "partition_undeclared",
                            format!(
                                "the partition `{}` is not declared by the manifest",
                                entry.name
                            ),
                        )
                    })?;
                    let allowed = declared.media_types.clone();
                    let previous = previous_roots
                        .iter()
                        .filter_map(|tree| {
                            tree.entries
                                .iter()
                                .find(|e| e.name == entry.name && e.kind == Kind::Tree)
                                .map(|e| e.digest.clone())
                        })
                        .collect::<Vec<_>>();
                    let mut sources = PartitionSources::default();
                    self.check_partition(
                        &entry.name,
                        &entry.digest,
                        &allowed,
                        &previous,
                        &previous_alias_maps,
                        &mut all_policy_ids,
                        &mut all_policy_aliases,
                        &mut sources,
                        1,
                    )?;
                    // One schema per partition, at most: two schemas is the
                    // same ambiguity as two manifests — nobody guesses which
                    // one validates the set.
                    let schemas = sources.schemas.len();
                    if schemas > 1 {
                        return Err(invalid(
                            "schema_ambiguous",
                            format!(
                                "the partition `{}` holds {schemas} schemas: at most one",
                                entry.name
                            ),
                        ));
                    }
                    // A partition that declares a schema and ships none would
                    // be accepted here and refused at every data plane's load
                    // gate — fail-closed, but the error belongs to the push.
                    if declared.schema && sources.schemas.is_empty() {
                        return Err(invalid(
                            "schema_missing",
                            format!(
                                "the partition `{}` declares a schema and the commit carries none",
                                entry.name
                            ),
                        ));
                    }
                    // The set-level semantic check the data plane's load gate
                    // runs — the same code, run where the error still belongs
                    // to whoever pushed. Without this, a schema-incompatible
                    // policy is stored, mirrored, and turns into a 503 at
                    // every plane serving the ledger.
                    let runtime = manifest.runtimes.get(&declared.runtime).ok_or_else(|| {
                        invalid(
                            "manifest_rejected",
                            format!("partition `{}` names an undeclared runtime", entry.name),
                        )
                    })?;
                    let plugin =
                        permguard_languages::language(&runtime.language.name).ok_or_else(|| {
                            invalid(
                                "runtime_gate",
                                format!(
                                    "no built-in plugin for the language `{}`",
                                    runtime.language.name
                                ),
                            )
                        })?;
                    let named: Vec<(&str, &[u8])> = sources
                        .policies
                        .iter()
                        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
                        .collect();
                    plugin
                        .validate_set(
                            &named,
                            sources.schemas.first().map(|(_, bytes)| bytes.as_slice()),
                        )
                        .map_err(|error| invalid("schema_unsatisfied", error))?;
                }
                Kind::Commit => unreachable!("entries never reference commits: enforced at decode"),
            }
        }
        policy_id::check_uniqueness(all_policy_ids.iter().map(String::as_str))
            .map_err(|e| invalid("policy_id_rejected", e.to_string()))?;
        policy_id::check_alias_uniqueness(all_policy_aliases.iter().map(String::as_str))
            .map_err(|e| invalid("policy_alias_rejected", e.to_string()))?;
        Ok(())
    }

    /// Walk one snapshot tree collecting `alias → id` for every policy entry.
    fn collect_aliases(&self, tree: &Tree, map: &mut BTreeMap<String, String>) -> Result<()> {
        for entry in &tree.entries {
            match entry.kind {
                Kind::Tree => {
                    let subtree = self.load_tree(&entry.digest)?;
                    self.collect_aliases(&subtree, map)?;
                }
                Kind::Blob => {
                    if let (Some(alias), Some(id)) = (
                        entry.annotations.get(ANNOTATION_POLICY_ALIAS),
                        entry.annotations.get(ANNOTATION_POLICY_ID),
                    ) {
                        map.insert(alias.clone(), id.clone());
                    }
                }
                Kind::Commit => unreachable!("entries never reference commits: enforced at decode"),
            }
        }
        Ok(())
    }

    /// One partition subtree, recursively: media types, identity cascade.
    #[allow(clippy::too_many_arguments)]
    fn check_partition(
        &self,
        path: &str,
        tree_digest: &Digest,
        allowed_media_types: &[String],
        previous_trees: &[Digest],
        previous_alias_maps: &[BTreeMap<String, String>],
        policy_ids: &mut Vec<String>,
        policy_aliases: &mut Vec<String>,
        sources: &mut PartitionSources,
        depth: usize,
    ) -> Result<()> {
        if depth > limits::MAX_TREE_DEPTH {
            return Err(invalid("limit", "tree depth exceeds the model limit"));
        }
        let tree = self.load_tree(tree_digest)?;
        let previous: Vec<Tree> = previous_trees
            .iter()
            .map(|digest| self.load_tree(digest))
            .collect::<Result<_>>()?;

        for entry in &tree.entries {
            let entry_path = format!("{path}/{}", entry.name);
            match entry.kind {
                Kind::Tree => {
                    let previous_subtrees = previous
                        .iter()
                        .filter_map(|tree| {
                            tree.entries
                                .iter()
                                .find(|e| e.name == entry.name && e.kind == Kind::Tree)
                                .map(|e| e.digest.clone())
                        })
                        .collect::<Vec<_>>();
                    self.check_partition(
                        &entry_path,
                        &entry.digest,
                        allowed_media_types,
                        &previous_subtrees,
                        previous_alias_maps,
                        policy_ids,
                        policy_aliases,
                        sources,
                        depth + 1,
                    )?;
                }
                Kind::Blob => {
                    let blob = self.load_blob(&entry.digest)?;
                    if !allowed_media_types.contains(&blob.media_type) {
                        return Err(invalid(
                            "media_type_not_allowed",
                            format!("`{}` is not allowed in this partition", blob.media_type),
                        ));
                    }
                    if permguard_languages::languages()
                        .iter()
                        .any(|plugin| plugin.schema_media_type() == Some(blob.media_type.as_str()))
                    {
                        sources
                            .schemas
                            .push((entry_path.clone(), blob.data.clone()));
                    }
                    if blob.media_type.starts_with(POLICY_FAMILY_PREFIX) {
                        self.check_policy_identity(
                            &entry_path,
                            entry,
                            &blob.media_type,
                            &blob.data,
                            &previous,
                            previous_alias_maps,
                            policy_ids,
                            policy_aliases,
                        )?;
                        sources
                            .policies
                            .push((entry_path.clone(), blob.data.clone()));
                    }
                }
                Kind::Commit => unreachable!("entries never reference commits: enforced at decode"),
            }
        }
        Ok(())
    }

    /// The identity cascade of one policy entry, recomputed and compared.
    #[allow(clippy::too_many_arguments)]
    fn check_policy_identity(
        &self,
        path: &str,
        entry: &object::TreeEntry,
        media_type: &str,
        source: &[u8],
        previous_trees: &[Tree],
        previous_alias_maps: &[BTreeMap<String, String>],
        policy_ids: &mut Vec<String>,
        policy_aliases: &mut Vec<String>,
    ) -> Result<()> {
        let annotated = entry.annotations.get(ANNOTATION_POLICY_ID).ok_or_else(|| {
            invalid(
                "policy_id_missing",
                format!("the policy `{path}` carries no {ANNOTATION_POLICY_ID} annotation"),
            )
        })?;
        if !entry.annotations.contains_key(ANNOTATION_POLICY_KIND) {
            return Err(invalid(
                "policy_kind_missing",
                format!("the policy `{path}` carries no {ANNOTATION_POLICY_KIND} annotation"),
            ));
        }

        // The alias annotation must mirror the source: both present and
        // equal, or both absent — the tree never says something the file
        // does not.
        let declared = declared_alias(media_type, source);
        let annotated_alias = entry.annotations.get(ANNOTATION_POLICY_ALIAS);
        match (&declared, annotated_alias) {
            (Some(declared), Some(alias)) if declared == alias => {}
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "policy_alias_mismatch",
                    format!(
                        "the policy `{path}` annotates an alias that does not mirror the source's @alias"
                    ),
                ));
            }
        }

        // Rule 1 hook: the same logical path in the parent tree(s).
        let previous_ids: Vec<String> = previous_trees
            .iter()
            .filter_map(|tree| {
                tree.entries
                    .iter()
                    .find(|e| e.name == entry.name && e.kind == Kind::Blob)
                    .and_then(|e| e.annotations.get(ANNOTATION_POLICY_ID).cloned())
            })
            .collect();
        let previous_by_path: Vec<&str> = previous_ids.iter().map(String::as_str).collect();

        // Rule 2 hook: the alias, anywhere in the parent snapshot(s).
        let alias_ids: Vec<String> = match &declared {
            Some(alias) => previous_alias_maps
                .iter()
                .filter_map(|map| map.get(alias).cloned())
                .collect(),
            None => Vec::new(),
        };
        let previous_by_alias: Vec<&str> = alias_ids.iter().map(String::as_str).collect();

        let resolved: ResolvedId =
            policy_id::resolve_id(path, &previous_by_path, &previous_by_alias, source)
                .map_err(|e| invalid("policy_id_rejected", e.to_string()))?;

        if resolved.id() != annotated {
            return Err(invalid(
                "policy_id_mismatch",
                format!(
                    "the policy `{path}` annotates id `{annotated}` but the cascade resolves `{}`",
                    resolved.id()
                ),
            ));
        }
        policy_ids.push(annotated.clone());
        if let Some(alias) = declared {
            policy_aliases.push(alias);
        }
        Ok(())
    }

    // ---- graph walks ----

    /// Everything reachable from `start` that is not reachable through
    /// `stop`: the region a push adds, the delta a pull sends.
    fn walk_region(&self, start: &Digest, stop: &BTreeSet<Digest>) -> Result<BTreeSet<Digest>> {
        let mut region = BTreeSet::new();
        let mut queue = vec![start.clone()];
        while let Some(digest) = queue.pop() {
            if stop.contains(&digest) || region.contains(&digest) {
                continue;
            }
            if region.len() >= MAX_HISTORY_WALK {
                return Err(EngineError::Internal {
                    detail: "history walk limit exceeded".into(),
                });
            }
            let Some(bytes) = self.store.get_object(&digest)? else {
                // Absent objects still belong to the region: the caller
                // decides whether absence is an error (commit) or work (pull).
                region.insert(digest);
                continue;
            };
            let object = object::decode(&bytes)
                .map_err(|e| invalid("object_rejected", format!("{digest}: {e}")))?;
            region.insert(digest);
            match object {
                Object::Commit(commit) => {
                    queue.push(commit.tree.clone());
                    queue.push(commit.manifest.clone());
                    queue.extend(commit.predecessors.iter().cloned());
                }
                Object::Tree(tree) => {
                    queue.extend(tree.entries.iter().map(|e| e.digest.clone()));
                }
                Object::Blob(_) => {}
            }
        }
        Ok(region)
    }

    /// The full closure of a commit — used to stop walks.
    fn reachable_from(&self, start: &Digest) -> Result<BTreeSet<Digest>> {
        self.walk_region(start, &BTreeSet::new())
    }

    /// Whether `ancestor` is reachable from `descendant` along predecessors.
    fn is_ancestor(&self, ancestor: &Digest, descendant: &Digest) -> Result<bool> {
        let mut queue = vec![descendant.clone()];
        let mut seen = BTreeSet::new();
        while let Some(digest) = queue.pop() {
            if digest == *ancestor {
                return Ok(true);
            }
            if !seen.insert(digest.clone()) || seen.len() >= MAX_HISTORY_WALK {
                continue;
            }
            if let Ok(commit) = self.load_commit(&digest) {
                queue.extend(commit.predecessors);
            }
        }
        Ok(false)
    }

    /// Whether a commit is reachable from any existing ref — branch creation.
    fn reachable_from_any_ref(&self, target: &Digest) -> Result<bool> {
        for (_, state) in self.store.list_refs()? {
            if self.reachable_from(&state.head)?.contains(target) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn kind_of(&self, digest: &Digest, decoded: &BTreeMap<Digest, Object>) -> Result<Kind> {
        if let Some(object) = decoded.get(digest) {
            return Ok(object.kind());
        }
        let bytes = self
            .store
            .get_object(digest)?
            .ok_or_else(|| EngineError::NotFound {
                what: format!("object {digest}"),
            })?;
        let object = object::decode(&bytes)
            .map_err(|e| invalid("object_rejected", format!("{digest}: {e}")))?;
        Ok(object.kind())
    }

    fn load_commit(&self, digest: &Digest) -> Result<Commit> {
        match self.load_object(digest)? {
            Object::Commit(commit) => Ok(commit),
            _ => Err(invalid(
                "kind_mismatch",
                format!("{digest} is not a commit"),
            )),
        }
    }

    fn load_tree(&self, digest: &Digest) -> Result<Tree> {
        match self.load_object(digest)? {
            Object::Tree(tree) => Ok(tree),
            _ => Err(invalid("kind_mismatch", format!("{digest} is not a tree"))),
        }
    }

    fn load_blob(&self, digest: &Digest) -> Result<object::Blob> {
        match self.load_object(digest)? {
            Object::Blob(blob) => Ok(blob),
            _ => Err(invalid("kind_mismatch", format!("{digest} is not a blob"))),
        }
    }

    fn load_object(&self, digest: &Digest) -> Result<Object> {
        let bytes = self
            .store
            .get_object(digest)?
            .ok_or_else(|| EngineError::NotFound {
                what: format!("object {digest}"),
            })?;
        object::decode(&bytes).map_err(|e| invalid("object_rejected", format!("{digest}: {e}")))
    }

    // ---- statements ----

    /// The current signed statement for a ref: the cache when it still
    /// matches `(head, counter)`, a fresh signature otherwise.
    fn current_statement(
        &self,
        name: &str,
        state: &RefState,
        signer: HeadSigner<'_>,
    ) -> Result<Vec<u8>> {
        // Served only when it matches the current ref — the cache never
        // becomes a second source of truth.
        if let Some(cached) = self.store.read_signature(name)?
            && let Ok(envelope) = permguard_objects::statement::SignedHead::decode(&cached)
            && let Ok(statement) = envelope.statement_unverified()
            && statement.digest == state.head
            && statement.counter == state.counter
        {
            return Ok(cached);
        }
        let statement = HeadStatement {
            zone: self.identity.zone_id.clone(),
            ledger: self.identity.ledger_id.clone(),
            r#ref: name.to_string(),
            digest: state.head.clone(),
            counter: state.counter,
            signed_at: now(),
        };
        let envelope = signer(&statement)?;
        self.store.write_signature(name, &envelope)?;
        Ok(envelope)
    }

    fn sign_and_cache(
        &self,
        name: &str,
        state: &RefState,
        signer: HeadSigner<'_>,
    ) -> Result<CommitPushResponse> {
        let statement = HeadStatement {
            zone: self.identity.zone_id.clone(),
            ledger: self.identity.ledger_id.clone(),
            r#ref: name.to_string(),
            digest: state.head.clone(),
            counter: state.counter,
            signed_at: now(),
        };
        let envelope = signer(&statement)?;
        self.store.write_signature(name, &envelope)?;
        Ok(CommitPushResponse {
            head: state.head.clone(),
            counter: state.counter,
            statement: envelope,
        })
    }

    fn answer_with_statement(&self, name: &str, state: RefState) -> Result<CommitPushResponse> {
        let statement = self.store.read_signature(name)?.unwrap_or_default();
        Ok(CommitPushResponse {
            head: state.head,
            counter: state.counter,
            statement,
        })
    }

    /// Bytes currently stored in this ledger's objects, for the quota.
    fn ledger_bytes(&self) -> Result<u64> {
        fn sum(directory: &std::path::Path) -> std::io::Result<u64> {
            let mut total = 0;
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                if meta.is_dir() {
                    total += sum(&entry.path())?;
                } else {
                    total += meta.len();
                }
            }
            Ok(total)
        }
        let objects = self.store.root().join("objects");
        if !objects.exists() {
            return Ok(0);
        }
        sum(&objects).map_err(|e| EngineError::Internal {
            detail: format!("sizing the ledger: {e}"),
        })
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}
