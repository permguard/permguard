// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Memberships (WP-4.1): direct, bilateral grants between two Host identities, on the volume
//! under `host/members/` (owner decisions of 2026-10-09).
//!
//! ```text
//! host/members/
//! ├── FORMAT                             the layout version, 1
//! ├── journal.cborseq                    authoritative, hash-chained transitions
//! ├── snapshot.cbor                      rebuildable summary, replaced atomically
//! ├── invites/<sha256(token)>.cbor       the invitation; never the token
//! └── manifests/<membership_id>/
//!     ├── current.cose
//!     └── history/<epoch>-<digest>.cose
//! ```
//!
//! | Transition                            | Who                     | Journal entry | Manifest               |
//! | ------------------------------------- | ----------------------- | ------------- | ---------------------- |
//! | invitation issued, revoked            | the coordinator         | `invited`, `invite_revoked` | none     |
//! | enrollment: invitation consumed       | the member, in a proven session | `enrolled` | none, `pending` |
//! | approve, reject                       | the coordinator         | `manifest`    | epoch 1                |
//! | suspend, resume, fence, revoke        | the coordinator         | `manifest`    | the successor          |
//! | revoke asked by the member            | the member, in a session | `manifest`   | the successor, `revoked` |
//! | join                                  | the member              | `joined`      | none, `pending`        |
//! | manifest accepted                     | the member              | `manifest`    | the coordinator's      |
//! | orphaned on an identity reset         | the resetting Host      | `orphaned`    | none                   |
//!
//! Every transition is one operation of the mutation engine (WP-3.6): the store writes only
//! inside it, the entry naming the operation. Every manifest revision is a new epoch, the
//! successor naming its predecessor's digest: the epoch is the fence, and the same epoch with
//! another digest is equivocation.

pub mod appraisal;
pub mod member;
pub mod record;
pub mod reset;
pub mod service;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Selector;
use permguard_core::domains::{digest as domain, protected};
use permguard_core::keys::{Jwk, Sign as _};
use permguard_objects::cbor;
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::crypto::thumbprint::{self, KeySet};
use permguard_objects::digest::Digest;

use crate::identity::record::{RecordError, uuid_text, uuid_v7};
use crate::identity::{self, Identity};
use crate::keys::record::Binding;
use crate::keys::ring::{
    CONTROL_ATTEST, DATA_ATTEST, HOST_IDENTITY, HOST_OPERATIONS, REGISTERED, Ring, RingError,
    verify_binding,
};
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Applying, Domain, Observed};
use crate::session::record::Operation as SessionOperation;
use crate::storage::volume::Volume;
use crate::storage::write::{read_view, replace_view};
use crate::storage::{Dir, StorageError, format, sequence};

use record::{
    EnrollRequest, Entry, HostRef, Invitation, Kind, LeasePolicy, Manifest, OperatorApproval,
    Pending, RingPin, RingStatement, Role, Status, Task, TaskType, chain, manifest_digest,
};

/// The directory below `host/`.
pub const DIRECTORY: &str = "members";
pub const FORMAT: &str = "FORMAT";
pub const JOURNAL: &str = "journal.cborseq";
pub const SNAPSHOT: &str = "snapshot.cbor";
pub const INVITES: &str = "invites";
pub const MANIFESTS: &str = "manifests";
pub const CURRENT: &str = "current.cose";
pub const HISTORY: &str = "history";
/// The layout version `FORMAT` holds.
pub const LAYOUT_VERSION: u64 = 1;

/// The mutation domain.
pub const DOMAIN: &str = "memberships";
/// The operations.
pub const INVITE: &str = "members.invite";
pub const INVITE_REVOKE: &str = "members.invite.revoke";
pub const ENROLL: &str = "members.enroll";
pub const APPROVE: &str = "members.approve";
pub const REJECT: &str = "members.reject";
pub const SUSPEND: &str = "members.suspend";
pub const RESUME: &str = "members.resume";
pub const FENCE: &str = "members.fence";
pub const REVOKE_PLAN: &str = "members.revoke.plan";
pub const REVOKE_RUN: &str = "members.revoke.run";
pub const REVOKE_PEER: &str = "members.revoke.peer";
pub const JOIN: &str = "members.join";
pub const SYNC: &str = "members.sync";
pub const ORPHAN: &str = "members.orphan";
/// A membership this Host coordinates, ended by its identity reset.
pub const END_ON_RESET: &str = "members.reset";
/// The appraisal of an active membership's assurance binding: renewed or revoked (WP-4.2).
pub const APPRAISE: &str = "members.appraise";

/// The audit actions.
pub const AUDIT_INVITED: &str = "host.membership.invited";
pub const AUDIT_INVITE_REVOKED: &str = "host.membership.invite_revoked";
pub const AUDIT_ENROLLED: &str = "host.membership.enrolled";
pub const AUDIT_APPROVED: &str = "host.membership.approved";
pub const AUDIT_REJECTED: &str = "host.membership.rejected";
pub const AUDIT_SUSPENDED: &str = "host.membership.suspended";
pub const AUDIT_RESUMED: &str = "host.membership.resumed";
pub const AUDIT_FENCED: &str = "host.membership.fenced";
pub const AUDIT_REVOKE_PLANNED: &str = "host.membership.revoke_planned";
pub const AUDIT_REVOKED: &str = "host.membership.revoked";
pub const AUDIT_JOINED: &str = "host.membership.joined";
pub const AUDIT_SYNCED: &str = "host.membership.synced";
pub const AUDIT_ORPHANED: &str = "host.membership.orphaned";
pub const AUDIT_APPRAISED: &str = "host.membership.appraised";
/// One operator approval an approval or an appraisal took, inside its operation (WP-4.2).
pub const AUDIT_ASSURANCE_APPROVED: &str = "host.membership.assurance_approved";
/// A binding an appraisal revoked, with its principal, reason and controls (WP-4.2).
pub const AUDIT_ASSURANCE_REVOKED: &str = "host.membership.assurance_revoked";

/// The longest an invitation lives, and how long when the request names no expiry (decided in
/// the package, 2026-10-09).
pub const INVITE_MAX_SECONDS: u64 = 7 * 86_400;
pub const INVITE_DEFAULT_SECONDS: u64 = 86_400;
/// How long a manifest is valid from its issue.
pub const MANIFEST_LIFETIME_SECONDS: u64 = 365 * 86_400;
/// The most journal entries one store reads: far beyond any real history.
const MAX_ENTRIES: usize = 1_000_000;

/// The lease policy a membership signs when the approval names none.
pub const DEFAULT_LEASE_POLICY: LeasePolicy = LeasePolicy {
    max_session_seconds: 3600,
    offline_grace_seconds: 86_400,
    clock_skew_seconds: 30,
    dormant_after_seconds: 30 * 86_400,
    revoke_after_seconds: 90 * 86_400,
};

/// Why a membership operation was not applied.
#[derive(Debug)]
pub enum MembershipError {
    /// A request this store never writes: malformed, out of its bounds or contradicting itself.
    Invalid(String),
    /// No invitation or membership of that id.
    Unknown(String),
    /// The revision named is not the current one.
    Conflict { expected: u64, current: u64 },
    /// The transition does not leave this status.
    Transition { from: Status, to: Status },
    /// An approval asked for more than the request.
    Widened(String),
    /// No Plane declared the task (WP-4.4 fills the registry).
    TaskUnserved(String),
    /// A control wants a verifier this Host has not registered, or the evidence names one it does
    /// not know (WP-4.2).
    AssuranceUnavailable(String),
    /// A control a task depends on has no current accepted assurance binding (WP-4.2).
    AssuranceRefused(String),
    /// An enrollment refused: the peer is told one code whatever the reason.
    Enrollment(String),
    /// A manifest with the epoch held and another digest.
    Equivocation(String),
    /// A manifest that is not the exact successor of the one held.
    NotSuccessor(String),
    /// A manifest, a binding or a ring statement that does not verify.
    Unverified(String),
    /// A ring needed for signing or pinning is not composed, or not ready.
    Ring(String),
    /// The journal or a file could not be read or written.
    Storage(String),
    /// The coordinator refused, or could not be reached: its stable code and the local reason.
    Remote { code: String, reason: String },
}

impl fmt::Display for MembershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "{detail}"),
            Self::Unknown(detail) => write!(f, "{detail}"),
            Self::Conflict { expected, current } => write!(
                f,
                "the revision named is {expected}, and the membership is at {current}"
            ),
            Self::Transition { from, to } => {
                write!(f, "a membership that is {from} does not become {to}")
            }
            Self::Widened(detail) => write!(f, "an approval may narrow, never widen: {detail}"),
            Self::TaskUnserved(detail) => write!(f, "{detail}"),
            Self::AssuranceUnavailable(detail) => write!(f, "{detail}"),
            Self::AssuranceRefused(detail) => write!(f, "assurance refused: {detail}"),
            Self::Enrollment(detail) => write!(f, "the enrollment is refused: {detail}"),
            Self::Equivocation(detail) => write!(f, "equivocation: {detail}"),
            Self::NotSuccessor(detail) => write!(f, "not the successor: {detail}"),
            Self::Unverified(detail) => write!(f, "does not verify: {detail}"),
            Self::Ring(detail) => write!(f, "{detail}"),
            Self::Storage(detail) => write!(f, "the membership store: {detail}"),
            Self::Remote { code, reason } => {
                write!(f, "the coordinator answered `{code}`: {reason}")
            }
        }
    }
}

impl std::error::Error for MembershipError {}

impl From<StorageError> for MembershipError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<RecordError> for MembershipError {
    fn from(error: RecordError) -> Self {
        Self::Storage(error.to_string())
    }
}

impl MembershipError {
    /// Whether the store may have written before failing: the engine leaves the intent for
    /// recovery.
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Storage(_))
    }
}

/// The task types this Host can act in, by role: what the Planes declare in the composition
/// (owner decision of 2026-10-09; WP-4.4 registers the real handlers). Approval refuses a task
/// the coordinator cannot act in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities(BTreeSet<(TaskType, Role)>);

impl Capabilities {
    /// Declares that this Host acts as `role` in `task`.
    pub fn declare(mut self, task: TaskType, role: Role) -> Self {
        self.0.insert((task, role));
        self
    }

    pub fn acts(&self, task: TaskType, role: Role) -> bool {
        self.0.contains(&(task, role))
    }
}

/// An invitation's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteState {
    Issued,
    Consumed,
    Revoked,
}

impl InviteState {
    pub fn as_str(self, expired: bool) -> &'static str {
        match self {
            Self::Issued if expired => "expired",
            Self::Issued => "issued",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
        }
    }
}

/// One membership as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// This Host's role in it.
    pub role: Role,
    pub status: Status,
    pub request: Pending,
    /// The manifest in force, its envelope and its digest.
    pub manifest: Option<(Manifest, Vec<u8>, Digest)>,
    /// One more at every entry about the membership.
    pub revision: u64,
    pub updated_at: u64,
}

impl Held {
    pub fn epoch(&self) -> u64 {
        self.manifest
            .as_ref()
            .map_or(0, |(manifest, ..)| manifest.epoch)
    }
}

#[derive(Debug, Default, Clone)]
struct State {
    seq: u64,
    /// The bytes of the last entry: what the next one chains to.
    last: Option<Vec<u8>>,
    invites: BTreeMap<[u8; 16], (Invitation, InviteState)>,
    memberships: BTreeMap<[u8; 16], Held>,
    /// The manifests each membership issued or accepted, by epoch.
    history: BTreeMap<[u8; 16], Vec<Vec<u8>>>,
    /// The journal entry each manifest was recorded at, by membership and epoch: what a bundle's
    /// frontier rebuilds the memberships it projects from.
    manifest_seq: BTreeMap<([u8; 16], u64), u64>,
    /// The coordinator's statements each manifest it issued was signed against, by membership
    /// and epoch.
    statements: BTreeMap<([u8; 16], u64), Vec<RingStatement>>,
    /// `(revision, target)` of every entry an operation made.
    operations: BTreeMap<[u8; 16], (u64, String)>,
}

/// The membership store of one Host.
pub struct Store {
    dir: Dir,
    invites: Dir,
    manifests: Dir,
    state: RwLock<State>,
    /// Serializes appends: the chain is a function of the order.
    writing: Mutex<()>,
    /// Set by an identity reset once it starts settling: no invitation, enrollment, approval or
    /// join is taken from then on in this process.
    fenced: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

/// What a coordinator needs to sign a manifest: its identity and its rings.
pub struct Coordinator<'a> {
    pub identity: &'a Identity,
    pub rings: &'a [Arc<Ring>],
}

impl Coordinator<'_> {
    fn host_ref(&self) -> HostRef {
        HostRef {
            host_id: self.identity.host_id(),
            epoch: self.identity.epoch(),
            fingerprint: self.identity.first_fingerprint().to_owned(),
        }
    }

    fn ring(&self, id: &str) -> Result<&Ring, MembershipError> {
        self.rings
            .iter()
            .find(|ring| ring.id() == id)
            .map(AsRef::as_ref)
            .ok_or_else(|| MembershipError::Ring(format!("this Host composes no ring `{id}`")))
    }

    /// The statement of `ring` as a pin and as the keys that verify under it.
    fn statement(&self, id: &str) -> Result<RingStatement, MembershipError> {
        statement_of(self.ring(id)?)
    }
}

/// The statement of `ring` as this Host presents it: its published keys and the identity-signed
/// binding of their set. Refused while the ring holds no binding of its epoch.
pub fn statement_of(ring: &Ring) -> Result<RingStatement, MembershipError> {
    let statement = ring
        .statement()
        .map_err(|error| MembershipError::Ring(error.to_string()))?;
    let binding = statement.binding.ok_or_else(|| {
        MembershipError::Ring(format!(
            "the ring `{}` holds no identity-signed binding of its epoch yet",
            statement.ring
        ))
    })?;
    Ok(RingStatement {
        ring: statement.ring,
        epoch: statement.epoch,
        suite: statement.suite,
        keys: statement
            .keys
            .iter()
            .map(|jwk| {
                serde_json::to_string(jwk).map_err(|error| MembershipError::Ring(error.to_string()))
            })
            .collect::<Result<_, _>>()?,
        binding,
    })
}

/// The rings a task needs pinned, by owner: the coordinator's operations ring always signs the
/// manifest; each task adds the ring that signs what its provider sends.
pub fn rings_needed(tasks: &[Task]) -> BTreeSet<(Role, &'static str)> {
    let mut needed = BTreeSet::from([(Role::Coordinator, HOST_OPERATIONS)]);
    for task in tasks {
        needed.insert(match task.task_type {
            TaskType::PolicyMirror | TaskType::EventsImport => (Role::Coordinator, CONTROL_ATTEST),
            TaskType::DecisionsShip | TaskType::EventsShip => (Role::Member, DATA_ATTEST),
            TaskType::AuditCheckpoints => (Role::Member, HOST_OPERATIONS),
            TaskType::ZoneSecrets => (Role::Coordinator, HOST_OPERATIONS),
        });
    }
    needed
}

/// Whether `inner` covers nothing `outer` does not: its prefix inside `outer`, and its
/// descendants only when `outer` covers that prefix whole.
pub fn selector_within(inner: &Selector, outer: &Selector) -> bool {
    outer.contains(inner.prefix())
        && (!inner.covers_descendants() || outer.covers_whole(inner.prefix()))
}

/// Whether `asked` is a narrowing of `offered`: the same task and type, its selector, resource
/// types and limits within, never optional where it was required.
fn task_within(asked: &Task, offered: &Task) -> bool {
    asked.task_id == offered.task_id
        && asked.task_type == offered.task_type
        && selector_within(&asked.selector, &offered.selector)
        && asked.resource_types.iter().all(|kind| {
            offered.resource_types.contains(kind) || offered.resource_types.iter().any(|t| t == "*")
        })
        && asked.limits.within(&offered.limits)
        && asked.required == offered.required
        && asked.assurance_requirements == offered.assurance_requirements
}

/// Checks `tasks` within `selector` and, when `offered` is given, each a narrowing of the offered
/// task of its id.
fn check_tasks(
    selector: &Selector,
    tasks: &[Task],
    offered: Option<(&Selector, &[Task])>,
) -> Result<(), MembershipError> {
    if tasks.is_empty() || tasks.len() > record::MAX_TASKS {
        return Err(MembershipError::Invalid(format!(
            "a membership grants 1 to {} tasks",
            record::MAX_TASKS
        )));
    }
    let mut named = BTreeSet::new();
    for task in tasks {
        // What the records refuse to read back is refused before anything is written.
        if !named.insert(task.task_id.as_str()) {
            return Err(MembershipError::Invalid(format!(
                "the task `{}` is named twice",
                task.task_id
            )));
        }
        task.check()
            .map_err(|error| MembershipError::Invalid(error.0))?;
        // Every requirement names a registered control.
        appraisal::required(std::slice::from_ref(task))?;
        if !selector_within(&task.selector, selector) {
            return Err(MembershipError::Invalid(format!(
                "the task `{}` reaches outside the membership's selector",
                task.task_id
            )));
        }
    }
    if let Some((outer, offered)) = offered {
        if !selector_within(selector, outer) {
            return Err(MembershipError::Widened(
                "the selector reaches outside the one offered".to_owned(),
            ));
        }
        for task in tasks {
            let Some(original) = offered.iter().find(|held| held.task_id == task.task_id) else {
                return Err(MembershipError::Widened(format!(
                    "the task `{}` was not offered",
                    task.task_id
                )));
            };
            if !task_within(task, original) {
                return Err(MembershipError::Widened(format!(
                    "the task `{}` asks for more than was offered",
                    task.task_id
                )));
            }
        }
    }
    Ok(())
}

fn rank(profile: AssuranceProfile) -> u8 {
    match profile {
        AssuranceProfile::Development => 0,
        AssuranceProfile::Production => 1,
        AssuranceProfile::Regulated => 2,
    }
}

fn random<const N: usize>() -> Result<[u8; N], MembershipError> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| MembershipError::Invalid("the OS random source refused".to_owned()))?;
    Ok(bytes)
}

fn fresh_id(now: u64) -> Result<[u8; 16], MembershipError> {
    Ok(uuid_v7(now.saturating_mul(1000), random()?))
}

/// The Ed25519 key pair an invitation's token derives: its seed is SHA-256 of the registered
/// domain and the token (owner decision of 2026-10-10). The coordinator keeps only the public key,
/// so nothing it holds can sign a proof.
fn token_key(token: &[u8]) -> Ed25519KeyPair {
    let seed: [u8; 32] = Sha256::new()
        .chain_update(domain::MEMBERSHIP_TOKEN_KEY.as_bytes())
        .chain_update(token)
        .finalize()
        .into();
    Ed25519KeyPair::from_seed_unchecked(&seed)
        .unwrap_or_else(|_| unreachable!("every 32-byte seed is an Ed25519 key"))
}

/// The public key of the token's key pair: what the coordinator keeps of an invitation.
pub fn token_public(token: &[u8]) -> [u8; 32] {
    let mut public = [0u8; 32];
    public.copy_from_slice(token_key(token).public_key().as_ref());
    public
}

/// What an enrollment's token proof signs: the domain, both Host ids and the connection's RFC
/// 9266 exporter.
fn token_message(coordinator: &[u8; 16], member: &[u8; 16], exporter: &[u8; 32]) -> Vec<u8> {
    let mut message = domain::MEMBERSHIP_ENROLL.as_bytes().to_vec();
    message.extend_from_slice(coordinator);
    message.extend_from_slice(member);
    message.extend_from_slice(exporter);
    message
}

/// The token proof a member computes: the token key's Ed25519 signature over the coordinator,
/// itself and the connection's exporter, valid in that session only.
pub fn token_proof(
    token: &[u8],
    coordinator: &[u8; 16],
    member: &[u8; 16],
    exporter: &[u8; 32],
) -> [u8; 64] {
    let mut proof = [0u8; 64];
    proof.copy_from_slice(
        token_key(token)
            .sign(&token_message(coordinator, member, exporter))
            .as_ref(),
    );
    proof
}

/// Whether `proof` is the token proof of the key `public` for that session.
fn token_proof_verifies(
    public: &[u8; 32],
    coordinator: &[u8; 16],
    member: &[u8; 16],
    exporter: &[u8; 32],
    proof: &[u8; 64],
) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(&token_message(coordinator, member, exporter), proof)
        .is_ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Verifies a ring statement presented by `owner` (a verified identity chain) at `now`: the
/// binding under the identity key its `kid` names, and the keys digesting to the set it binds.
pub fn verify_statement(
    statement: &RingStatement,
    owner: &identity::Verified,
    now: Option<u64>,
) -> Result<Binding, MembershipError> {
    if !REGISTERED.contains(&statement.ring.as_str()) || statement.ring == HOST_IDENTITY {
        return Err(MembershipError::Unverified(format!(
            "`{}` is not a ring a membership pins",
            statement.ring
        )));
    }
    let sign1 = Sign1::decode(&statement.binding)
        .map_err(|error| MembershipError::Unverified(error.to_string()))?;
    let header = sign1
        .header()
        .map_err(|error| MembershipError::Unverified(error.to_string()))?;
    let signer = std::str::from_utf8(&header.kid)
        .ok()
        .filter(|text| !text.is_empty() && !text.starts_with('0'))
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|epoch| *epoch >= 1 && *epoch <= owner.public_keys.len())
        .ok_or_else(|| {
            MembershipError::Unverified(format!(
                "the binding of `{}` names no identity epoch of its Host",
                statement.ring
            ))
        })?;
    let binding = match now {
        Some(now) => verify_binding(
            &statement.binding,
            owner.suite,
            &owner.public_keys[signer - 1],
            &owner.host_id,
            &statement.ring,
            now,
        )
        .map_err(MembershipError::Unverified)?,
        None => {
            let payload = sign1
                .verify(
                    owner.suite,
                    &owner.public_keys[signer - 1],
                    protected::HOST_RING_BINDING,
                )
                .map_err(|error| MembershipError::Unverified(error.to_string()))?;
            let binding = Binding::decode(payload)?;
            if binding.host_id != owner.host_id || binding.ring != statement.ring {
                return Err(MembershipError::Unverified(
                    "the binding names another Host or ring".to_owned(),
                ));
            }
            binding
        }
    };
    if binding.epoch != statement.epoch || binding.suite != statement.suite {
        return Err(MembershipError::Unverified(format!(
            "the binding of `{}` is of another epoch or suite than the statement",
            statement.ring
        )));
    }
    let mut thumbprints = Vec::with_capacity(statement.keys.len());
    for text in &statement.keys {
        let jwk: Jwk = serde_json::from_str(text).map_err(|error| {
            MembershipError::Unverified(format!("a key of `{}`: {error}", statement.ring))
        })?;
        let thumbprint = thumbprint::jwk_thumbprint_of(&jwk).ok_or_else(|| {
            MembershipError::Unverified(format!(
                "a key of `{}` is no key of a suite",
                statement.ring
            ))
        })?;
        // Its `kid` names the key it holds, in the ring it is presented for.
        if jwk.kid != format!("{}:{thumbprint}", statement.ring) {
            return Err(MembershipError::Unverified(format!(
                "a key of `{}` names another kid than its thumbprint",
                statement.ring
            )));
        }
        thumbprints.push(thumbprint);
    }
    let refs: Vec<&str> = thumbprints.iter().map(String::as_str).collect();
    let digest = KeySet::new(&statement.ring, statement.epoch, statement.suite, &refs)
        .and_then(|set| set.digest())
        .map_err(|error| MembershipError::Unverified(error.to_string()))?;
    if digest != binding.key_set_digest {
        return Err(MembershipError::Unverified(format!(
            "the keys of `{}` do not digest to the set its binding names",
            statement.ring
        )));
    }
    Ok(binding)
}

/// The public key a JWK of `suite` holds.
fn public_of(text: &str) -> Option<(String, Suite, Vec<u8>)> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let jwk: Jwk = serde_json::from_str(text).ok()?;
    let suite = crate::keys::ring::suite_of(&jwk)?;
    let mut bytes = B64.decode(&jwk.x).ok()?;
    if let Some(y) = jwk.y.as_deref() {
        bytes.insert(0, 0x04);
        bytes.extend(B64.decode(y).ok()?);
    }
    (bytes.len() == suite.public_key_len()).then_some((jwk.kid, suite, bytes))
}

/// Verifies a manifest in the blueprint's order (owner decisions of 2026-10-09): the
/// coordinator's identity, already verified from its pin; the binding of its `host.operations`
/// set under that identity; the operations keys digesting to that set; the manifest under the
/// key its `kid` names. Answers the manifest and its digest.
pub fn verify_manifest(
    envelope: &[u8],
    coordinator: &identity::Verified,
    statements: &[RingStatement],
) -> Result<(Manifest, Digest), MembershipError> {
    let sign1 =
        Sign1::decode(envelope).map_err(|error| MembershipError::Unverified(error.to_string()))?;
    let claimed = Manifest::decode(sign1.payload_unverified())?;
    let pin = claimed
        .ring_pins
        .iter()
        .find(|pin| pin.owner == Role::Coordinator && pin.ring == HOST_OPERATIONS)
        .ok_or_else(|| {
            MembershipError::Unverified(
                "the manifest pins no coordinator `host.operations`".to_owned(),
            )
        })?;
    let statement = statements
        .iter()
        .find(|statement| {
            statement.ring == HOST_OPERATIONS
                && statement.epoch == pin.epoch
                && statement.binding == pin.binding
        })
        .ok_or_else(|| {
            MembershipError::Unverified(
                "no statement of the coordinator's `host.operations` at the pinned epoch"
                    .to_owned(),
            )
        })?;
    let binding = verify_statement(statement, coordinator, None)?;
    if binding.key_set_digest != pin.key_set_digest {
        return Err(MembershipError::Unverified(
            "the pinned `host.operations` digest is not the one its binding names".to_owned(),
        ));
    }
    let header = sign1
        .header()
        .map_err(|error| MembershipError::Unverified(error.to_string()))?;
    let (_, suite, public_key) = statement
        .keys
        .iter()
        .filter_map(|text| public_of(text))
        .find(|(kid, ..)| kid.as_bytes() == header.kid.as_slice())
        .ok_or_else(|| {
            MembershipError::Unverified(
                "the manifest is signed by no key of the bound operations set".to_owned(),
            )
        })?;
    let payload = sign1
        .verify(suite, &public_key, protected::MEMBERSHIP_MANIFEST)
        .map_err(|error| MembershipError::Unverified(error.to_string()))?;
    let manifest = Manifest::decode(payload)?;
    if manifest.coordinator.host_id != coordinator.host_id {
        return Err(MembershipError::Unverified(
            "the manifest names another coordinator".to_owned(),
        ));
    }
    Ok((manifest, manifest_digest(envelope)))
}

/// How a manifest stands against the one held: the exact current one is a retry, the next epoch
/// naming the held digest is the successor, anything else is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Succession {
    Retry,
    Successor,
}

pub fn succession(
    held: Option<(u64, &Digest)>,
    manifest: &Manifest,
    digest: &Digest,
) -> Result<Succession, MembershipError> {
    match held {
        None if manifest.epoch == 1 && manifest.previous.is_none() => Ok(Succession::Successor),
        None => Err(MembershipError::NotSuccessor(
            "the first manifest held is the genesis, epoch 1".to_owned(),
        )),
        Some((epoch, held)) if manifest.epoch == epoch => {
            if held == digest {
                Ok(Succession::Retry)
            } else {
                Err(MembershipError::Equivocation(format!(
                    "epoch {epoch} with another digest"
                )))
            }
        }
        Some((epoch, held))
            if manifest.epoch == epoch + 1 && manifest.previous.as_ref() == Some(held) =>
        {
            Ok(Succession::Successor)
        }
        Some((epoch, _)) if manifest.epoch < epoch => Err(MembershipError::NotSuccessor(format!(
            "epoch {} below the {epoch} held: rollback",
            manifest.epoch
        ))),
        Some((epoch, _)) => Err(MembershipError::NotSuccessor(format!(
            "epoch {} does not succeed the {epoch} held",
            manifest.epoch
        ))),
    }
}

/// The new invitation an operator asks for.
#[derive(Debug, Clone)]
pub struct NewInvite {
    pub selector: Selector,
    pub tasks: Vec<Task>,
    pub expires: Option<u64>,
    pub expected_fingerprint: Option<String>,
    pub min_assurance: Option<AssuranceProfile>,
}

/// What an enrolling peer brings: its verified chain, its declared profile and the connection's
/// exporter, all from the proven session.
pub struct Enrolling<'a> {
    pub peer: &'a identity::Verified,
    /// The presentation `peer` was verified from, kept with the pending membership.
    pub presentation: &'a [u8],
    pub declared_assurance: AssuranceProfile,
    pub exporter: &'a [u8; 32],
}

/// An approval's narrowing.
#[derive(Debug, Clone)]
pub struct Narrow {
    pub selector: Selector,
    pub tasks: Vec<Task>,
}

/// What an approval or an appraisal brings for the controls the tasks require (WP-4.2): the
/// coordinator's appraisal, the operator's approvals, the evidence, and who asks.
#[derive(Debug, Clone, Copy)]
pub struct Offered<'a> {
    pub appraisal: &'a appraisal::Appraisal,
    pub approvals: &'a [appraisal::Approval],
    pub evidence: &'a [appraisal::Evidence],
    pub principal: &'a str,
}

impl Store {
    /// Opens `host/members/` on `volume`, laying it out when absent, and replays the journal,
    /// checking its chain.
    pub fn open(volume: &Volume) -> Result<Arc<Self>, MembershipError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        match read_view(&dir, FORMAT, format::VIEW)? {
            None => replace_view(&dir, FORMAT, format::VIEW, &LAYOUT_VERSION.to_be_bytes())?,
            Some(bytes) if bytes == LAYOUT_VERSION.to_be_bytes() => {}
            Some(_) => {
                return Err(MembershipError::Storage(format!(
                    "{} is a layout this build does not read",
                    dir.child_path(FORMAT).display()
                )));
            }
        }
        let invites = dir.subdir(INVITES, true)?;
        let manifests = dir.subdir(MANIFESTS, true)?;
        let journal = sequence::recover(&dir, JOURNAL, record::MAX_RECORD_BYTES * 2)?;
        if journal.items.len() > MAX_ENTRIES {
            return Err(MembershipError::Storage(
                "the journal is beyond its bound".to_owned(),
            ));
        }
        let mut state = State::default();
        for item in journal.items {
            let bytes =
                cbor::encode(&item).map_err(|error| MembershipError::Storage(error.to_string()))?;
            let entry = Entry::decode(&bytes)?;
            apply(&mut state, &entry, &bytes)?;
        }
        Ok(Arc::new(Self {
            dir,
            invites,
            manifests,
            state: RwLock::new(state),
            writing: Mutex::new(()),
            fenced: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Appends `entry` (its `seq` and `previous` filled here), then applies it: the journal is
    /// written before the change shows.
    /// Serializes a mutation: its checks, its files and its entry happen under one lock, so two
    /// concurrent operations never both pass a check only one may.
    fn begin(&self) -> MutexGuard<'_, ()> {
        self.writing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Fences the store for an identity reset: what would create authority under the identity
    /// being retired is refused from now on in this process.
    pub fn fence(&self) {
        let _writing = self.begin();
        self.fenced.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn unfenced(&self) -> Result<(), MembershipError> {
        if self.fenced.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MembershipError::Invalid(
                "an identity reset is under way: nothing new is taken under this identity"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Appends one entry under the lock `begin` took: applied first to a copy of the state, so
    /// an entry the history refuses is never written; a manifest's files follow the check.
    #[allow(clippy::too_many_arguments)]
    fn commit(
        &self,
        _writing: &MutexGuard<'_, ()>,
        applying: &Applying<'_>,
        kind: Kind,
        subject: [u8; 16],
        epoch: Option<u64>,
        at: u64,
        detail: Option<Vec<u8>>,
    ) -> Result<Entry, MembershipError> {
        self.commit_with(
            _writing,
            applying,
            kind,
            subject,
            epoch,
            at,
            detail,
            Vec::new(),
        )
    }

    /// [`Self::commit`], the entry carrying `statements`.
    #[allow(clippy::too_many_arguments)]
    fn commit_with(
        &self,
        _writing: &MutexGuard<'_, ()>,
        applying: &Applying<'_>,
        kind: Kind,
        subject: [u8; 16],
        epoch: Option<u64>,
        at: u64,
        detail: Option<Vec<u8>>,
        statements: Vec<RingStatement>,
    ) -> Result<Entry, MembershipError> {
        let (seq, previous) = {
            let state = self.read();
            (state.seq + 1, chain(state.last.as_deref()))
        };
        let entry = Entry {
            seq,
            kind,
            subject,
            epoch,
            at,
            operation_id: Some(*applying.operation_id().as_bytes()),
            previous,
            detail,
            statements,
        };
        let bytes = entry.encode()?;
        // What the next start reads back is refused here, determinately: an entry over its bound
        // or one the history does not take never reaches the journal.
        Entry::decode(&bytes)
            .map_err(|error| MembershipError::Invalid(format!("the entry: {}", error.0)))?;
        let mut next = self.read().clone();
        apply(&mut next, &entry, &bytes).map_err(|error| {
            MembershipError::Invalid(format!("the history does not take the entry: {error}"))
        })?;
        sequence::append(&self.dir, JOURNAL, &bytes)?;
        *self.state.write().unwrap_or_else(PoisonError::into_inner) = next;
        // The views follow the journal, best effort: the journal is authoritative.
        if let (Kind::Manifest, Some(envelope), Some(epoch)) =
            (kind, entry.detail.as_deref(), epoch)
            && let Err(error) =
                self.keep_manifest(&subject, envelope, epoch, &manifest_digest(envelope))
        {
            tracing::warn!(
                event.name = "host.membership.view_unwritten",
                component = "host",
                error = %error,
                "a manifest view was not written; the journal stays authoritative"
            );
        }
        self.write_snapshot();
        Ok(entry)
    }

    /// The summary view: what a reader can see without replaying the journal. Best effort: the
    /// journal is authoritative.
    fn write_snapshot(&self) {
        let summary = {
            let state = self.read();
            let memberships: Vec<cbor::Value> = state
                .memberships
                .iter()
                .map(|(id, held)| {
                    cbor::Value::Array(vec![
                        cbor::Value::Bytes(id.to_vec()),
                        cbor::Value::Text(held.status.as_str().to_owned()),
                        cbor::Value::Int(i64::try_from(held.epoch()).unwrap_or(i64::MAX)),
                    ])
                })
                .collect();
            cbor::encode(&cbor::Value::Map(vec![
                (
                    cbor::Value::Int(1),
                    cbor::Value::Int(i64::try_from(state.seq).unwrap_or(i64::MAX)),
                ),
                (
                    cbor::Value::Int(2),
                    cbor::Value::Text(chain(state.last.as_deref()).to_string()),
                ),
                (cbor::Value::Int(3), cbor::Value::Array(memberships)),
            ]))
        };
        if let Ok(bytes) = summary
            && let Err(error) = replace_view(&self.dir, SNAPSHOT, format::VIEW, &bytes)
        {
            tracing::warn!(
                event.name = "host.membership.snapshot_unwritten",
                component = "host",
                error = %error,
                "the membership snapshot was not replaced; the journal stays authoritative"
            );
        }
    }

    /// Writes a manifest's files: the history entry once, then `current.cose`.
    fn keep_manifest(
        &self,
        membership_id: &[u8; 16],
        envelope: &[u8],
        epoch: u64,
        digest: &Digest,
    ) -> Result<(), MembershipError> {
        let dir = self.manifests.subdir(&hex(membership_id), true)?;
        let history = dir.subdir(HISTORY, true)?;
        let name = format!(
            "{epoch}-{}.cose",
            digest.to_string().trim_start_matches("sha256:")
        );
        replace_view(&history, &name, format::VIEW, envelope)?;
        replace_view(&dir, CURRENT, format::VIEW, envelope)?;
        Ok(())
    }

    // ---- reads ----

    /// Every invitation, with its state at `now`; never a token.
    pub fn invitations(&self, now: u64) -> Vec<(Invitation, &'static str)> {
        self.read()
            .invites
            .values()
            .map(|(invitation, state)| {
                (invitation.clone(), state.as_str(now >= invitation.expires))
            })
            .collect()
    }

    /// Every membership, by id.
    pub fn memberships(&self) -> Vec<([u8; 16], Held)> {
        self.read()
            .memberships
            .iter()
            .map(|(id, held)| (*id, held.clone()))
            .collect()
    }

    pub fn membership(&self, id: &[u8; 16]) -> Option<Held> {
        self.read().memberships.get(id).cloned()
    }

    /// The manifests of `id`, oldest first.
    pub fn history(&self, id: &[u8; 16]) -> Vec<Vec<u8>> {
        self.read().history.get(id).cloned().unwrap_or_default()
    }

    /// The pins memberships hold of their peers that are not terminal: `(host_id, first
    /// fingerprint)`, what a session accepts a peer by.
    pub fn pins(&self) -> Vec<([u8; 16], String)> {
        self.read()
            .memberships
            .values()
            .filter(|held| !held.status.is_terminal())
            .map(|held| {
                let peer = match held.role {
                    Role::Coordinator => &held.request.member,
                    Role::Member => &held.request.coordinator,
                };
                (peer.host_id, peer.fingerprint.clone())
            })
            .collect()
    }

    /// The sequence of the journal's last entry: where a bundle's frontier fixes the memberships.
    pub fn seq(&self) -> u64 {
        self.read().seq
    }

    /// The memberships this Host coordinates as they stood at the journal entry `seq`: each with
    /// the last manifest recorded by then, its envelope and digest, and the request it answered.
    #[allow(clippy::type_complexity)]
    pub fn coordinated_at(
        &self,
        seq: u64,
    ) -> Vec<(Pending, Manifest, Vec<u8>, Digest, Vec<RingStatement>)> {
        let state = self.read();
        state
            .memberships
            .iter()
            .filter(|(_, held)| held.role == Role::Coordinator)
            .filter_map(|(id, held)| {
                let epoch = state
                    .manifest_seq
                    .range((*id, 0)..=(*id, u64::MAX))
                    .filter(|(_, at)| **at <= seq)
                    .map(|((_, epoch), _)| *epoch)
                    .max()?;
                let envelope = state
                    .history
                    .get(id)?
                    .get(usize::try_from(epoch.checked_sub(1)?).ok()?)?
                    .clone();
                let manifest = Sign1::decode(&envelope)
                    .ok()
                    .and_then(|sign1| Manifest::decode(sign1.payload_unverified()).ok())?;
                let digest = manifest_digest(&envelope);
                let statements = state
                    .statements
                    .get(&(*id, epoch))
                    .cloned()
                    .unwrap_or_default();
                Some((held.request.clone(), manifest, envelope, digest, statements))
            })
            .collect()
    }

    /// What the journal shows of `operation_id`.
    pub fn observe(&self, operation_id: &OperationId) -> Option<Observed> {
        self.read()
            .operations
            .get(operation_id.as_bytes())
            .map(|(revision, target)| Observed {
                revision: *revision,
                target: Some(target.clone()),
            })
    }

    fn held(&self, id: &[u8; 16]) -> Result<Held, MembershipError> {
        self.membership(id)
            .ok_or_else(|| MembershipError::Unknown(format!("no membership `{}`", uuid_text(id))))
    }

    // ---- the coordinator ----

    /// Issues an invitation: answers it and the token, which is never kept.
    pub fn invite(
        &self,
        applying: &Applying<'_>,
        new: NewInvite,
        by: &str,
        now: u64,
    ) -> Result<(Invitation, [u8; 32]), MembershipError> {
        let writing = self.begin();
        self.unfenced()?;
        check_tasks(&new.selector, &new.tasks, None)?;
        let expires = new.expires.unwrap_or(now + INVITE_DEFAULT_SECONDS);
        if expires <= now || expires > now + INVITE_MAX_SECONDS {
            return Err(MembershipError::Invalid(format!(
                "an invitation expires within {} days",
                INVITE_MAX_SECONDS / 86_400
            )));
        }
        if let Some(fingerprint) = &new.expected_fingerprint {
            Digest::parse(fingerprint).map_err(|_| {
                MembershipError::Invalid(
                    "an expected fingerprint is `sha256:` and 64 hex digits".to_owned(),
                )
            })?;
        }
        let token = random::<32>()?;
        let invitation = Invitation {
            invite_id: fresh_id(now)?,
            token_key: token_public(&token),
            selector: new.selector,
            tasks: new.tasks,
            expires,
            expected_fingerprint: new.expected_fingerprint,
            min_assurance: new.min_assurance,
            max_uses: 1,
            created_at: now,
            created_by: by.to_owned(),
        };
        let bytes = invitation.encode()?;
        self.commit(
            &writing,
            applying,
            Kind::Invited,
            invitation.invite_id,
            None,
            now,
            Some(bytes.clone()),
        )?;
        // The view follows the journal, best effort.
        if let Err(error) = replace_view(
            &self.invites,
            &format!("{}.cbor", hex(&invitation.invite_id)),
            format::VIEW,
            &bytes,
        ) {
            tracing::warn!(
                event.name = "host.membership.view_unwritten",
                component = "host",
                error = %error,
                "an invitation view was not written; the journal stays authoritative"
            );
        }
        Ok((invitation, token))
    }

    /// Revokes an invitation not used yet.
    pub fn revoke_invite(
        &self,
        applying: &Applying<'_>,
        invite_id: &[u8; 16],
        now: u64,
    ) -> Result<Invitation, MembershipError> {
        let writing = self.begin();
        let (invitation, state) = self.read().invites.get(invite_id).cloned().ok_or_else(|| {
            MembershipError::Unknown(format!("no invitation `{}`", uuid_text(invite_id)))
        })?;
        if state != InviteState::Issued {
            return Err(MembershipError::Invalid(format!(
                "the invitation is {}",
                state.as_str(false)
            )));
        }
        self.commit(
            &writing,
            applying,
            Kind::InviteRevoked,
            *invite_id,
            None,
            now,
            None,
        )?;
        Ok(invitation)
    }

    /// Checks an enrollment without writing: the invitation, the proof, the peer, the request.
    /// Answers the pending membership the enrollment would create.
    pub fn check_enroll(
        &self,
        coordinator: &Coordinator<'_>,
        enrolling: &Enrolling<'_>,
        request: &EnrollRequest,
        now: u64,
    ) -> Result<Pending, MembershipError> {
        let refused = |detail: &str| MembershipError::Enrollment(detail.to_owned());
        let (invitation, state) = self
            .read()
            .invites
            .get(&request.invite_id)
            .cloned()
            .ok_or_else(|| refused("no invitation of that id"))?;
        if state != InviteState::Issued {
            return Err(refused("the invitation was used or revoked"));
        }
        if now >= invitation.expires {
            return Err(refused("the invitation expired"));
        }
        let coordinator_id = coordinator.identity.host_id();
        if !token_proof_verifies(
            &invitation.token_key,
            &coordinator_id,
            &enrolling.peer.host_id,
            enrolling.exporter,
            &request.token_proof,
        ) {
            return Err(refused("the token proof does not verify"));
        }
        let peer = enrolling.peer;
        if request.member.host_id != peer.host_id
            || request.member.epoch != peer.epoch
            || request.member.fingerprint != peer.first_fingerprint()
        {
            return Err(refused("the request names another Host than the session's"));
        }
        if let Some(expected) = &invitation.expected_fingerprint
            && !expected.eq_ignore_ascii_case(peer.first_fingerprint())
        {
            return Err(refused("the invitation expects another member"));
        }
        if let Some(min) = invitation.min_assurance
            && rank(enrolling.declared_assurance) < rank(min)
        {
            return Err(refused(
                "the declared profile is below the invitation's floor",
            ));
        }
        check_tasks(
            &request.selector,
            &request.tasks,
            Some((&invitation.selector, &invitation.tasks)),
        )
        .map_err(|error| MembershipError::Enrollment(error.to_string()))?;
        let mut rings = BTreeSet::new();
        for statement in &request.ring_statements {
            if !rings.insert(statement.ring.clone()) {
                return Err(refused("a ring is presented twice"));
            }
            verify_statement(statement, peer, Some(now))
                .map_err(|error| MembershipError::Enrollment(error.to_string()))?;
        }
        // Exactly the rings the requested tasks need the member's keys of: none missing, which
        // would leave a pending membership no approval can sign, and none beyond.
        let needed: BTreeSet<String> = rings_needed(&request.tasks)
            .into_iter()
            .filter(|(owner, _)| *owner == Role::Member)
            .map(|(_, ring)| ring.to_owned())
            .collect();
        if rings != needed {
            return Err(refused(
                "the ring statements are not the rings the requested tasks need",
            ));
        }
        Ok(Pending {
            membership_id: fresh_id(now)?,
            invite_id: request.invite_id,
            coordinator: coordinator.host_ref(),
            member: request.member.clone(),
            selector: request.selector.clone(),
            tasks: request.tasks.clone(),
            member_assurance: enrolling.declared_assurance,
            ring_statements: request.ring_statements.clone(),
            requested_at: now,
            coordinator_address: None,
            identity: Some(presented(enrolling)?),
        })
        .and_then(|pending| {
            // What the journal keeps stays within a record's bound, its entry's fields included.
            if pending.encode()?.len() > record::MAX_RECORD_BYTES - 4096 {
                return Err(refused(
                    "the request and its presentation are too large to keep",
                ));
            }
            Ok(pending)
        })
    }

    /// Records an enrollment checked by [`Self::check_enroll`]: the invitation consumed and the
    /// membership `pending`, one entry.
    pub fn enroll(
        &self,
        applying: &Applying<'_>,
        pending: &Pending,
        now: u64,
    ) -> Result<(), MembershipError> {
        let writing = self.begin();
        self.unfenced()?;
        if self
            .read()
            .invites
            .get(&pending.invite_id)
            .is_none_or(|(_, state)| *state != InviteState::Issued)
        {
            return Err(MembershipError::Enrollment(
                "the invitation was used or revoked".to_owned(),
            ));
        }
        self.commit(
            &writing,
            applying,
            Kind::Enrolled,
            pending.membership_id,
            None,
            now,
            Some(pending.encode()?),
        )?;
        Ok(())
    }

    fn expect(held: &Held, expected_revision: Option<u64>) -> Result<(), MembershipError> {
        if let Some(expected) = expected_revision
            && expected != held.revision
        {
            return Err(MembershipError::Conflict {
                expected,
                current: held.revision,
            });
        }
        Ok(())
    }

    /// Checks an approval without writing; answers the manifest it would sign and the operator
    /// approvals its binding cites, which the audit keeps whole.
    #[allow(clippy::too_many_arguments)]
    pub fn check_approve(
        &self,
        coordinator: &Coordinator<'_>,
        capabilities: &Capabilities,
        id: &[u8; 16],
        narrow: Option<&Narrow>,
        lease_policy: Option<LeasePolicy>,
        offered: &Offered<'_>,
        expected_revision: Option<u64>,
        now: u64,
    ) -> Result<(Manifest, Vec<RingStatement>, Vec<OperatorApproval>), MembershipError> {
        let held = self.held(id)?;
        Self::expect(&held, expected_revision)?;
        if held.role != Role::Coordinator || held.status != Status::Pending {
            return Err(MembershipError::Transition {
                from: held.status,
                to: Status::Active,
            });
        }
        let (selector, tasks) = match narrow {
            Some(narrow) => {
                check_tasks(
                    &narrow.selector,
                    &narrow.tasks,
                    Some((&held.request.selector, &held.request.tasks)),
                )?;
                (narrow.selector.clone(), narrow.tasks.clone())
            }
            None => (held.request.selector.clone(), held.request.tasks.clone()),
        };
        for task in &tasks {
            if !capabilities.acts(task.task_type, Role::Coordinator) {
                return Err(MembershipError::TaskUnserved(format!(
                    "no Plane of this Host acts in `{}` as the coordinator",
                    task.task_type.as_str()
                )));
            }
        }
        let lease_policy = lease_policy.unwrap_or(DEFAULT_LEASE_POLICY);
        lease_policy
            .check()
            .map_err(|error| MembershipError::Invalid(error.0))?;
        // The controls the granted tasks require, appraised against the pending request: a
        // declaration alone never meets what the policy wants appraised.
        let state = Digest::compute(&held.request.encode()?);
        let outcome = offered.appraisal.appraise(&appraisal::Request {
            membership_id: id,
            member: &held.request.member,
            declared: held.request.member_assurance,
            tasks: &tasks,
            approvals: offered.approvals,
            evidence: offered.evidence,
            principal: offered.principal,
            nonce: &appraisal::nonce(&coordinator.identity.host_id(), id, &state),
            now,
        })?;
        let (pins, statements) = self.pins_for(coordinator, &held.request, &tasks)?;
        Ok((
            Manifest {
                membership_id: *id,
                coordinator: coordinator.host_ref(),
                member: held.request.member.clone(),
                selector,
                tasks,
                member_assurance: held.request.member_assurance,
                min_assurance: self
                    .read()
                    .invites
                    .get(&held.request.invite_id)
                    .and_then(|(invitation, _)| invitation.min_assurance),
                assurance_binding: outcome.binding,
                ring_pins: pins,
                epoch: 1,
                lease_policy,
                previous: None,
                issued_at: now,
                not_after: now + MANIFEST_LIFETIME_SECONDS,
                status: Status::Active,
            },
            statements,
            outcome.approvals,
        ))
    }

    /// The pins of a manifest granting `tasks`, and the coordinator's statements behind its own.
    fn pins_for(
        &self,
        coordinator: &Coordinator<'_>,
        request: &Pending,
        tasks: &[Task],
    ) -> Result<(Vec<RingPin>, Vec<RingStatement>), MembershipError> {
        let mut pins = Vec::new();
        let mut statements = Vec::new();
        for (owner, ring) in rings_needed(tasks) {
            let statement = match owner {
                Role::Coordinator => {
                    let statement = coordinator.statement(ring)?;
                    statements.push(statement.clone());
                    statement
                }
                Role::Member => request
                    .ring_statements
                    .iter()
                    .find(|statement| statement.ring == ring)
                    .cloned()
                    .ok_or_else(|| {
                        MembershipError::Invalid(format!(
                            "the member presented no `{ring}`, which its tasks need pinned"
                        ))
                    })?,
            };
            let payload = Sign1::decode(&statement.binding)
                .map_err(|error| MembershipError::Unverified(error.to_string()))?;
            let binding = Binding::decode(payload.payload_unverified())?;
            pins.push(RingPin {
                owner,
                ring: ring.to_owned(),
                epoch: statement.epoch,
                key_set_digest: binding.key_set_digest,
                binding: statement.binding,
            });
        }
        Ok((pins, statements))
    }

    /// Signs and records `manifest` for a coordinator's transition.
    fn issue(
        &self,
        writing: &MutexGuard<'_, ()>,
        applying: &Applying<'_>,
        coordinator: &Coordinator<'_>,
        manifest: &Manifest,
        now: u64,
    ) -> Result<(Vec<u8>, Digest), MembershipError> {
        // The coordinator's statements of the rings it pins, as they stand at this signature: a
        // member verifies the manifest with them whatever the rings do after.
        let mut statements = Vec::new();
        for pin in manifest
            .ring_pins
            .iter()
            .filter(|pin| pin.owner == Role::Coordinator)
        {
            let statement = coordinator.statement(&pin.ring)?;
            if statement.epoch != pin.epoch || statement.binding != pin.binding {
                return Err(MembershipError::Ring(format!(
                    "`{}` moved since the manifest was checked: try again",
                    pin.ring
                )));
            }
            statements.push(statement);
        }
        let envelope = sign_manifest(coordinator.ring(HOST_OPERATIONS)?, manifest)?;
        let digest = manifest_digest(&envelope);
        self.commit_with(
            writing,
            applying,
            Kind::Manifest,
            manifest.membership_id,
            Some(manifest.epoch),
            now,
            Some(envelope.clone()),
            statements,
        )?;
        Ok((envelope, digest))
    }

    /// Approves a pending membership, narrowing when asked: the genesis manifest, epoch 1.
    pub fn approve(
        &self,
        applying: &Applying<'_>,
        coordinator: &Coordinator<'_>,
        manifest: &Manifest,
        now: u64,
    ) -> Result<(Vec<u8>, Digest), MembershipError> {
        let writing = self.begin();
        // A reset under way takes no activation; its own rejections still issue.
        if manifest.status == Status::Active {
            self.unfenced()?;
        }
        let held = self.held(&manifest.membership_id)?;
        if held.status != Status::Pending {
            return Err(MembershipError::Transition {
                from: held.status,
                to: manifest.status,
            });
        }
        self.issue(&writing, applying, coordinator, manifest, now)
    }

    /// The successor of `id`'s manifest with `status`: for reject (a genesis in status
    /// `rejected`), suspend, resume, fence and revoke.
    pub fn check_successor(
        &self,
        coordinator: &Coordinator<'_>,
        id: &[u8; 16],
        to: Status,
        expected_revision: Option<u64>,
        now: u64,
    ) -> Result<Manifest, MembershipError> {
        let held = self.held(id)?;
        Self::expect(&held, expected_revision)?;
        if held.role != Role::Coordinator || !held.status.allows(to) || to == Status::Orphaned {
            return Err(MembershipError::Transition {
                from: held.status,
                to,
            });
        }
        // `fence` keeps an active membership active; nothing else moves a status to itself.
        if to == held.status && to != Status::Active {
            return Err(MembershipError::Transition {
                from: held.status,
                to,
            });
        }
        match &held.manifest {
            None => {
                // A pending membership has no manifest: its rejection or expiry is a genesis;
                // its activation is an approval, never a successor.
                if !matches!(to, Status::Rejected | Status::Expired) {
                    return Err(MembershipError::Transition {
                        from: held.status,
                        to,
                    });
                }
                let (pins, _) = self.pins_for(coordinator, &held.request, &[])?;
                Ok(Manifest {
                    membership_id: *id,
                    coordinator: coordinator.host_ref(),
                    member: held.request.member.clone(),
                    selector: held.request.selector.clone(),
                    tasks: held.request.tasks.clone(),
                    member_assurance: held.request.member_assurance,
                    min_assurance: None,
                    assurance_binding: None,
                    ring_pins: pins,
                    epoch: 1,
                    lease_policy: DEFAULT_LEASE_POLICY,
                    previous: None,
                    issued_at: now,
                    not_after: now + MANIFEST_LIFETIME_SECONDS,
                    status: to,
                })
            }
            Some((manifest, _, digest)) => {
                let mut next = manifest.clone();
                next.epoch += 1;
                next.previous = Some(digest.clone());
                next.issued_at = now;
                next.not_after = now + MANIFEST_LIFETIME_SECONDS;
                next.status = to;
                // The coordinator's own pins follow its rings as they are now.
                let tasks = next.tasks.clone();
                let (pins, _) = self.pins_for(coordinator, &held.request, &tasks)?;
                next.ring_pins = pins;
                Ok(next)
            }
        }
    }

    /// Issues a successor checked by [`Self::check_successor`].
    pub fn transition(
        &self,
        applying: &Applying<'_>,
        coordinator: &Coordinator<'_>,
        manifest: &Manifest,
        now: u64,
    ) -> Result<(Vec<u8>, Digest), MembershipError> {
        let writing = self.begin();
        let held = self.held(&manifest.membership_id)?;
        if !held.status.allows(manifest.status) || held.epoch() + 1 != manifest.epoch {
            return Err(MembershipError::Transition {
                from: held.status,
                to: manifest.status,
            });
        }
        self.issue(&writing, applying, coordinator, manifest, now)
    }

    /// Checks an appraisal of an active membership without writing: its successor, a new epoch,
    /// with the binding renewed from what `offered` brings, or revoked when `revoke` is set.
    pub fn check_appraise(
        &self,
        coordinator: &Coordinator<'_>,
        id: &[u8; 16],
        offered: &Offered<'_>,
        revoke: bool,
        expected_revision: Option<u64>,
        now: u64,
    ) -> Result<(Manifest, Vec<OperatorApproval>), MembershipError> {
        let held = self.held(id)?;
        if held.role != Role::Coordinator || held.status != Status::Active {
            return Err(MembershipError::Transition {
                from: held.status,
                to: Status::Active,
            });
        }
        let Some((current, _, digest)) = &held.manifest else {
            return Err(MembershipError::Transition {
                from: held.status,
                to: Status::Active,
            });
        };
        let mut next =
            self.check_successor(coordinator, id, Status::Active, expected_revision, now)?;
        if revoke {
            if !offered.approvals.is_empty() || !offered.evidence.is_empty() {
                return Err(MembershipError::Invalid(
                    "a revocation takes no approval and no evidence".to_owned(),
                ));
            }
            let binding = current.assurance_binding.as_ref().ok_or_else(|| {
                MembershipError::Invalid("the membership has no assurance binding".to_owned())
            })?;
            if binding.verdict == record::Verdict::Revoked {
                return Err(MembershipError::Invalid(
                    "the assurance binding is already revoked".to_owned(),
                ));
            }
            next.assurance_binding = Some(appraisal::Appraisal::revoked(
                binding,
                offered.principal,
                now,
            ));
            return Ok((next, Vec::new()));
        }
        let outcome = offered.appraisal.appraise(&appraisal::Request {
            membership_id: id,
            member: &current.member,
            declared: current.member_assurance,
            tasks: &current.tasks,
            approvals: offered.approvals,
            evidence: offered.evidence,
            principal: offered.principal,
            nonce: &appraisal::nonce(&coordinator.identity.host_id(), id, digest),
            now,
        })?;
        if outcome.binding.is_none() {
            return Err(MembershipError::Invalid(
                "no task of the membership requires a control".to_owned(),
            ));
        }
        next.assurance_binding = outcome.binding;
        Ok((next, outcome.approvals))
    }

    /// What a `membership` session answers its member: the status, the manifests after
    /// `held_epoch` and the coordinator's statements of its pinned rings.
    pub fn answer(
        &self,
        coordinator: &Coordinator<'_>,
        id: &[u8; 16],
        peer: &[u8; 16],
        held_epoch: Option<u64>,
    ) -> Result<record::MembershipAnswer, MembershipError> {
        let _ = coordinator;
        // One reading of the state: the status, the manifests and their statements agree.
        let state = self.read();
        let held = state.memberships.get(id).ok_or_else(|| {
            MembershipError::Unknown("no membership of that id names this member".to_owned())
        })?;
        if held.role != Role::Coordinator || held.request.member.host_id != *peer {
            return Err(MembershipError::Unknown(
                "no membership of that id names this member".to_owned(),
            ));
        }
        let from = held_epoch.unwrap_or(0);
        let manifests: Vec<Vec<u8>> = state
            .history
            .get(id)
            .into_iter()
            .flatten()
            .skip(usize::try_from(from).unwrap_or(usize::MAX))
            .cloned()
            .collect();
        // The statements each manifest answered was signed against, once each.
        let mut statements: Vec<RingStatement> = Vec::new();
        for epoch in (from + 1)..=held.epoch() {
            for statement in state.statements.get(&(*id, epoch)).into_iter().flatten() {
                if !statements
                    .iter()
                    .any(|held| held.ring == statement.ring && held.epoch == statement.epoch)
                {
                    statements.push(statement.clone());
                }
            }
        }
        Ok(record::MembershipAnswer {
            status: held.status,
            manifests,
            ring_statements: statements,
        })
    }

    // ---- the member ----

    /// Records a joined membership on the member side: `pending`, with the coordinator's pin and
    /// address.
    pub fn join(
        &self,
        applying: &Applying<'_>,
        pending: &Pending,
        now: u64,
    ) -> Result<(), MembershipError> {
        let writing = self.begin();
        self.unfenced()?;
        if self.read().memberships.contains_key(&pending.membership_id) {
            return Err(MembershipError::Invalid(
                "a membership of that id is held already".to_owned(),
            ));
        }
        self.commit(
            &writing,
            applying,
            Kind::Joined,
            pending.membership_id,
            None,
            now,
            Some(pending.encode()?),
        )?;
        Ok(())
    }

    /// Checks the manifests a coordinator answered against the one held: each verified in order,
    /// each the exact successor of the one before. Answers the ones to record.
    pub fn check_sync(
        &self,
        id: &[u8; 16],
        coordinator: &identity::Verified,
        answer: &record::MembershipAnswer,
        now: u64,
    ) -> Result<Vec<(Manifest, Vec<u8>, Digest)>, MembershipError> {
        let held = self.held(id)?;
        if held.role != Role::Member
            || held.request.coordinator.host_id != coordinator.host_id
            || held.request.coordinator.fingerprint != coordinator.first_fingerprint()
        {
            return Err(MembershipError::Unknown(
                "no membership of that id names this coordinator".to_owned(),
            ));
        }
        let mut current = held
            .manifest
            .as_ref()
            .map(|(manifest, _, digest)| (manifest.epoch, digest.clone()));
        let mut status = held.status;
        let mut accepted = Vec::new();
        for envelope in &answer.manifests {
            let (manifest, digest) =
                verify_manifest(envelope, coordinator, &answer.ring_statements)?;
            // The manifest pins the two Hosts the member enrolled as, byte for byte.
            if manifest.membership_id != *id
                || manifest.member != held.request.member
                || manifest.coordinator.host_id != held.request.coordinator.host_id
                || manifest.coordinator.fingerprint != held.request.coordinator.fingerprint
            {
                return Err(MembershipError::Unverified(
                    "the manifest is of another membership, member or coordinator".to_owned(),
                ));
            }
            match succession(
                current.as_ref().map(|(epoch, digest)| (*epoch, digest)),
                &manifest,
                &digest,
            )? {
                Succession::Retry => continue,
                Succession::Successor => {
                    // Only the transitions of the table, never back from an end.
                    if !status.allows(manifest.status) || manifest.status == Status::Orphaned {
                        return Err(MembershipError::Transition {
                            from: status,
                            to: manifest.status,
                        });
                    }
                    // A coordinator narrows what the member asked for, never widens it.
                    check_tasks(
                        &manifest.selector,
                        &manifest.tasks,
                        Some((&held.request.selector, &held.request.tasks)),
                    )
                    .map_err(|error| match error {
                        MembershipError::Widened(detail) => MembershipError::Widened(detail),
                        other => MembershipError::Unverified(other.to_string()),
                    })?;
                    if manifest.not_after <= now {
                        return Err(MembershipError::Unverified(
                            "the manifest is past its `not_after`".to_owned(),
                        ));
                    }
                    status = manifest.status;
                    current = Some((manifest.epoch, digest.clone()));
                    accepted.push((manifest, envelope.clone(), digest));
                }
            }
        }
        Ok(accepted)
    }

    /// Records a manifest accepted by [`Self::check_sync`].
    pub fn accept(
        &self,
        applying: &Applying<'_>,
        manifest: &Manifest,
        envelope: &[u8],
        digest: &Digest,
        now: u64,
    ) -> Result<(), MembershipError> {
        let writing = self.begin();
        let held = self.held(&manifest.membership_id)?;
        let at = held
            .manifest
            .as_ref()
            .map(|(manifest, _, digest)| (manifest.epoch, digest));
        if succession(at, manifest, digest)? == Succession::Retry {
            return Ok(());
        }
        // Rechecked under the lock: an orphaning or another sync may have moved it since.
        if held.role != Role::Member || !held.status.allows(manifest.status) {
            return Err(MembershipError::Transition {
                from: held.status,
                to: manifest.status,
            });
        }
        self.commit(
            &writing,
            applying,
            Kind::Manifest,
            manifest.membership_id,
            Some(manifest.epoch),
            now,
            Some(envelope.to_vec()),
        )?;
        Ok(())
    }

    /// Marks a membership `orphaned` on an identity reset.
    pub fn orphan(
        &self,
        applying: &Applying<'_>,
        id: &[u8; 16],
        now: u64,
    ) -> Result<(), MembershipError> {
        let writing = self.begin();
        let held = self.held(id)?;
        // Only the resetting Host's memberships as a member are orphaned.
        if held.role != Role::Member || held.status.is_terminal() {
            return Err(MembershipError::Transition {
                from: held.status,
                to: Status::Orphaned,
            });
        }
        self.commit(&writing, applying, Kind::Orphaned, *id, None, now, None)?;
        Ok(())
    }
}

/// The enrolling member's presentation, checked to be the identity its session verified.
fn presented(enrolling: &Enrolling<'_>) -> Result<Vec<u8>, MembershipError> {
    let refused = || {
        MembershipError::Enrollment(
            "the presentation is not the identity the session proved".into(),
        )
    };
    let presentation = crate::session::record::Presentation::decode(enrolling.presentation)
        .map_err(|_| refused())?;
    let verified = identity::verify_published(
        &presentation.document,
        &presentation.successions,
        &presentation.first_public_key,
    )
    .map_err(|_| refused())?;
    if verified.host_id != enrolling.peer.host_id
        || verified.epoch != enrolling.peer.epoch
        || verified.first_fingerprint() != enrolling.peer.first_fingerprint()
    {
        return Err(refused());
    }
    Ok(enrolling.presentation.to_vec())
}

/// Applies one journal entry to the state, refusing one the history does not allow.
fn apply(state: &mut State, entry: &Entry, bytes: &[u8]) -> Result<(), MembershipError> {
    let corrupt =
        |detail: String| MembershipError::Storage(format!("journal entry {}: {detail}", entry.seq));
    if entry.seq != state.seq + 1 {
        return Err(corrupt(format!(
            "follows {}: the journal has a gap",
            state.seq
        )));
    }
    if entry.previous != chain(state.last.as_deref()) {
        return Err(corrupt("does not chain to the entry before".to_owned()));
    }
    let detail = || {
        entry
            .detail
            .as_deref()
            .ok_or_else(|| corrupt("carries no detail".to_owned()))
    };
    let mut revision = 0;
    match entry.kind {
        Kind::Invited => {
            let invitation = Invitation::decode(detail()?)?;
            if invitation.invite_id != entry.subject || state.invites.contains_key(&entry.subject) {
                return Err(corrupt("an invitation issued twice".to_owned()));
            }
            state
                .invites
                .insert(entry.subject, (invitation, InviteState::Issued));
        }
        Kind::InviteRevoked => match state.invites.get_mut(&entry.subject) {
            Some((_, invite_state @ InviteState::Issued)) => *invite_state = InviteState::Revoked,
            _ => return Err(corrupt("revokes no issued invitation".to_owned())),
        },
        Kind::Enrolled => {
            let pending = Pending::decode(detail()?)?;
            match state.invites.get_mut(&pending.invite_id) {
                Some((_, invite_state @ InviteState::Issued)) => {
                    *invite_state = InviteState::Consumed
                }
                _ => return Err(corrupt("consumes no issued invitation".to_owned())),
            }
            if pending.membership_id != entry.subject
                || state.memberships.contains_key(&entry.subject)
            {
                return Err(corrupt("a membership enrolled twice".to_owned()));
            }
            revision = 1;
            state.memberships.insert(
                entry.subject,
                Held {
                    role: Role::Coordinator,
                    status: Status::Pending,
                    request: pending,
                    manifest: None,
                    revision,
                    updated_at: entry.at,
                },
            );
        }
        Kind::Joined => {
            let pending = Pending::decode(detail()?)?;
            if pending.membership_id != entry.subject
                || state.memberships.contains_key(&entry.subject)
            {
                return Err(corrupt("a membership joined twice".to_owned()));
            }
            revision = 1;
            state.memberships.insert(
                entry.subject,
                Held {
                    role: Role::Member,
                    status: Status::Pending,
                    request: pending,
                    manifest: None,
                    revision,
                    updated_at: entry.at,
                },
            );
        }
        Kind::Manifest => {
            let envelope = detail()?;
            let sign1 = Sign1::decode(envelope).map_err(|error| corrupt(error.to_string()))?;
            let manifest = Manifest::decode(sign1.payload_unverified())?;
            let digest = manifest_digest(envelope);
            let held = state
                .memberships
                .get_mut(&entry.subject)
                .ok_or_else(|| corrupt("a manifest of no membership".to_owned()))?;
            let at = held
                .manifest
                .as_ref()
                .map(|(manifest, _, digest)| (manifest.epoch, digest));
            if manifest.membership_id != entry.subject
                || Some(manifest.epoch) != entry.epoch
                || succession(at, &manifest, &digest).map_err(|error| corrupt(error.to_string()))?
                    != Succession::Successor
            {
                return Err(corrupt(
                    "a manifest that does not succeed the one held".to_owned(),
                ));
            }
            if !held.status.allows(manifest.status) {
                return Err(corrupt(
                    "a manifest whose status the one held cannot take".to_owned(),
                ));
            }
            if !entry.statements.is_empty() {
                state
                    .statements
                    .insert((entry.subject, manifest.epoch), entry.statements.clone());
            }
            state
                .manifest_seq
                .insert((entry.subject, manifest.epoch), entry.seq);
            let held = state
                .memberships
                .get_mut(&entry.subject)
                .ok_or_else(|| corrupt("a manifest of no membership".to_owned()))?;
            held.status = manifest.status;
            held.manifest = Some((manifest, envelope.to_vec(), digest));
            held.revision += 1;
            held.updated_at = entry.at;
            revision = held.revision;
            state
                .history
                .entry(entry.subject)
                .or_default()
                .push(envelope.to_vec());
        }
        Kind::Orphaned => {
            let held = state
                .memberships
                .get_mut(&entry.subject)
                .ok_or_else(|| corrupt("orphans no membership".to_owned()))?;
            if held.status.is_terminal() {
                return Err(corrupt("orphans a terminal membership".to_owned()));
            }
            held.status = Status::Orphaned;
            held.revision += 1;
            held.updated_at = entry.at;
            revision = held.revision;
        }
    }
    if let Some(operation_id) = entry.operation_id {
        state
            .operations
            .insert(operation_id, (revision, uuid_text(&entry.subject)));
    }
    state.seq = entry.seq;
    state.last = Some(bytes.to_vec());
    Ok(())
}

/// The peers the memberships pin, for the sessions (WP-4.1): a membership that is not terminal
/// pins its peer's first fingerprint.
impl crate::session::peers::PinSource for Store {
    /// An active membership pins its peer for every session; a pending or suspended one only for
    /// a `membership` session; one that ended (revoked, rejected, expired) pins its member only
    /// for a `membership` session, on which the coordinator answers the manifest that ended it:
    /// the member's receipt. An orphaned membership pins nobody.
    fn pin(&self, host_id: &[u8; 16], operation: Option<SessionOperation>) -> Option<String> {
        self.read().memberships.values().find_map(|held| {
            let peer = match held.role {
                Role::Coordinator => &held.request.member,
                Role::Member => &held.request.coordinator,
            };
            let reading = operation == Some(SessionOperation::Membership);
            let reachable = match held.status {
                // An active membership pins its peer for every session.
                Status::Active => true,
                // One not yet approved, or suspended, only to read its manifests.
                Status::Pending | Status::Suspended => reading,
                // One that ended lets its member read how it ended, and nothing else.
                Status::Revoked | Status::Rejected | Status::Expired => {
                    reading && held.role == Role::Coordinator
                }
                Status::Orphaned => false,
            };
            (peer.host_id == *host_id && reachable).then(|| peer.fingerprint.clone())
        })
    }
}

/// Signs `manifest` under `operations`, the coordinator's `host.operations` ring.
pub fn sign_manifest(operations: &Ring, manifest: &Manifest) -> Result<Vec<u8>, MembershipError> {
    let kid = operations
        .active_key_id()
        .map_err(|error| MembershipError::Ring(error.to_string()))?;
    let envelope = Sign1::sign_with(
        operations.suite(),
        protected::MEMBERSHIP_MANIFEST,
        kid.as_str().as_bytes(),
        manifest.encode()?,
        |bytes| {
            let signature = operations.sign(bytes).map_err(|error| error.to_string())?;
            if signature.key_id() != &kid {
                return Err("the signing key rotated mid-signature".to_owned());
            }
            Ok(signature.bytes().to_vec())
        },
    )
    .map_err(|error| MembershipError::Ring(error.to_string()))?;
    envelope
        .encode()
        .map_err(|error| MembershipError::Ring(error.to_string()))
}

/// The membership store, as recovery sees it.
pub struct Memberships<'a>(pub &'a Store);

impl Domain for Memberships<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, _target: Option<&str>) -> Option<Observed> {
        self.0.observe(operation_id)
    }
}

/// A ring error, as a membership refusal.
impl From<RingError> for MembershipError {
    fn from(error: RingError) -> Self {
        Self::Ring(error.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests;
