// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ring registry (WP-3.1): `host/keys/<ring>/` on the volume.
//!
//! ```text
//! host/keys/<ring>/
//! ├── journal.cborseq          lifecycle and epoch transitions; authoritative
//! ├── ring.cbor                the materialized public view, rebuilt from the journal
//! ├── binding.cose             the identity-signed binding of the current set
//! ├── public/<thumbprint>.jwk  every key the ring ever published, kept for good
//! └── private/<thumbprint>.key through the key provider, 0600; destroyed at retirement
//! ```
//!
//! | State          | In the published set | Signs | Private half                          |
//! | -------------- | -------------------- | ----- | ------------------------------------- |
//! | prepublished   | yes                  | no    | held                                  |
//! | active         | yes                  | yes   | held                                  |
//! | retired-public | yes, for `retain`    | no    | destroyed once the signings in flight end |
//! | revoked        | no, at once          | no    | destroyed                             |
//! | archived       | no; `public/` keeps it | no  | destroyed                             |
//!
//! Exactly one key is active. The epoch rises at every change of the published set: a key
//! prepublished, archived or revoked out of it. Every transition is a journal entry written before
//! the change shows in `ring.cbor` or a key set, and an `operations` audit record; maintenance runs
//! at start and on the timer, serialized per ring, and is idempotent. An operator's rotation and
//! revocation are security mutations of the domain [`DOMAIN`] (owner decisions of 2026-10-08).
//!
//! A key's `kid` is `<ring>:<thumbprint>`; its files and its provider slot are named by the
//! thumbprint alone, the directory naming the ring.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

use permguard_core::audit::Fact;
use permguard_core::keys::{Jwk, KeyId, Maintenance, Signature};
use permguard_core::{AuditEvent, Subject};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::crypto::thumbprint::{self, KeySet};

use super::record::{
    Binding, Entry, KeyView, Kind, MAX_ENTRY_BYTES, MAX_REASON_BYTES, State, View,
};
use super::{FileKeyProvider, KeyError as ProviderError, KeyProvider, PublicKey};
use crate::identity::record::RecordError;
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Applying, Domain, Observed};
use crate::storage::volume::Volume;
use crate::storage::write::{Published, publish_immutable, read_view, replace_view};
use crate::storage::{Dir, StorageError, format, sequence};
use crate::time::TimeGuard;

/// The directory below `host/`.
pub const DIRECTORY: &str = "keys";
/// The ring's journal.
pub const JOURNAL: &str = "journal.cborseq";
/// The materialized view.
pub const VIEW: &str = "ring.cbor";
/// The identity-signed binding.
pub const BINDING: &str = "binding.cose";
/// The public halves.
pub const PUBLIC: &str = "public";
/// The private halves, through the key provider.
pub const PRIVATE: &str = "private";

/// The Host identity's ring: a view of the identity's keys, with no store of its own.
pub const HOST_IDENTITY: &str = "host.identity";
/// The Host's operations ring.
pub const HOST_OPERATIONS: &str = "host.operations";
/// The Control Plane's ring.
pub const CONTROL_ATTEST: &str = "control.attest";
/// The Data Plane's ring.
pub const DATA_ATTEST: &str = "data.attest";
/// The rings this build registers.
pub const REGISTERED: &[&str] = &[HOST_IDENTITY, HOST_OPERATIONS, CONTROL_ATTEST, DATA_ATTEST];

/// The most bytes a ring binding's envelope takes: its payload's bound, the protected header and
/// the signature. Checked before the envelope is parsed.
pub const MAX_BINDING_ENVELOPE_BYTES: usize = super::record::MAX_BINDING_BYTES + 512;
/// How long a ring binding is valid (owner decision of 2026-10-08).
pub const BINDING_LIFETIME: Duration = Duration::from_secs(30 * 86_400);
/// How long before its end a binding is issued again.
pub const BINDING_RENEWAL: Duration = Duration::from_secs(7 * 86_400);

/// The mutation domain an operator's rotation and revocation belong to.
pub const DOMAIN: &str = "keys";
/// An operator's rotation.
pub const ROTATE: &str = "keys.rotate";
/// The plan step of a revocation.
pub const REVOKE_PLAN: &str = "keys.revoke.plan";
/// The run step of a revocation.
pub const REVOKE_RUN: &str = "keys.revoke.run";
/// The `security` action of a rotation.
pub const AUDIT_ROTATED: &str = "host.keys.rotated";
/// The `security` action of a revocation plan.
pub const AUDIT_REVOKE_PLANNED: &str = "host.keys.revoke_planned";
/// The `security` action of a revocation.
pub const AUDIT_REVOKED: &str = "host.keys.revoked";
/// The `operations` action of every journal entry.
pub const AUDIT_TRANSITION: &str = "host.keys.transition";

/// How long each key spends in each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// How long a key is published before it signs.
    pub publish_ahead: Duration,
    /// How long a key signs before its successor takes over.
    pub rotate_every: Duration,
    /// How long a retired key stays in the published set: at least the longest retention.
    pub retain: Duration,
}

/// Why a ring refused or failed.
#[derive(Debug)]
pub enum RingError {
    Storage(StorageError),
    Provider(ProviderError),
    Record(RecordError),
    /// The journal or the files below the ring do not agree: the ring is not opened.
    Corrupt(String),
    /// The ring has no key to sign or publish with yet.
    NotReady(String),
    /// A transition that does not apply: nothing was written.
    Refused(String),
    /// A successor is prepublished already: a rotation waits for it.
    Pending(String),
    /// The ring holds no key of that kid.
    UnknownKey(String),
    /// The key is revoked already.
    Revoked(String),
    /// An operator's transition reached the journal and a later step of it failed: the ring
    /// changed, and the next maintenance completes it.
    Unfinished(String),
    /// The epoch the caller read is not the ring's.
    Conflict {
        expected: u64,
        current: u64,
    },
}

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "{error}"),
            Self::Provider(error) => write!(f, "{error}"),
            Self::Record(error) => write!(f, "{error}"),
            Self::Corrupt(detail)
            | Self::NotReady(detail)
            | Self::Refused(detail)
            | Self::Pending(detail)
            | Self::UnknownKey(detail)
            | Self::Revoked(detail)
            | Self::Unfinished(detail) => f.write_str(detail),
            Self::Conflict { expected, current } => write!(
                f,
                "the ring is at epoch {current}, not the {expected} the request read"
            ),
        }
    }
}

impl std::error::Error for RingError {}

impl From<StorageError> for RingError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<ProviderError> for RingError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl From<RecordError> for RingError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl RingError {
    /// Whether the failure may have left a write behind: a storage or provider failure, or a
    /// transition that reached the journal and did not finish.
    pub fn is_indeterminate(&self) -> bool {
        matches!(
            self,
            Self::Storage(_) | Self::Provider(_) | Self::Unfinished(_)
        )
    }
}

fn core_error(error: RingError) -> permguard_core::KeyError {
    match error {
        RingError::NotReady(detail) => permguard_core::KeyError::not_ready(detail),
        other => permguard_core::KeyError::backend(other.to_string()),
    }
}

/// What signs a ring binding: the Host identity.
pub trait Binder: Send + Sync {
    /// The Host the bindings name.
    fn host_id(&self) -> [u8; 16];
    /// The `kid` of the identity key that signs, `host.identity:<thumbprint>`: what a `bound`
    /// entry records.
    fn kid(&self) -> Result<String, String>;
    /// The identity key that signs now: a binding it did not sign is issued again.
    fn public_key(&self) -> PublicKey;
    /// A COSE_Sign1 `permguard.host.ring-binding.v1` over `payload`.
    fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, String>;
}

impl Binder for crate::identity::Identity {
    fn host_id(&self) -> [u8; 16] {
        crate::identity::Identity::host_id(self)
    }

    fn kid(&self) -> Result<String, String> {
        let public = crate::identity::Identity::public_key(self);
        thumbprint::jwk_thumbprint(public.suite, &public.bytes)
            .map(|thumbprint| thumbprint::kid(HOST_IDENTITY, &thumbprint))
            .map_err(|error| error.to_string())
    }

    fn public_key(&self) -> PublicKey {
        crate::identity::Identity::public_key(self)
    }

    fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        crate::identity::Identity::sign(
            self,
            permguard_core::domains::protected::HOST_RING_BINDING,
            payload,
        )
        .map_err(|error| error.to_string())
    }
}

/// Where a ring's transitions are recorded besides its journal: the `operations` audit.
pub trait Recorder: Send + Sync {
    fn record(&self, ring: &str, entry: &Entry);
}

impl Recorder for crate::audit::Engine {
    fn record(&self, ring: &str, entry: &Entry) {
        let mut facts = vec![
            ("ring", Fact::Text(ring)),
            ("kind", Fact::Text(entry.kind.as_str())),
            ("epoch", Fact::Uint(entry.epoch)),
        ];
        if let Some(reason) = &entry.reason {
            facts.push(("reason", Fact::Text(reason)));
        }
        let event = AuditEvent::new(AUDIT_TRANSITION, Subject::System("host"))
            .on(&entry.kid)
            .with_facts(&facts);
        if let Err(error) = self.append(&event, None) {
            tracing::error!(
                event.name = "host.keys.transition_unrecorded",
                component = "host",
                ring = ring,
                error = %error,
                "a key ring transition could not be recorded in the operations audit"
            );
        }
    }
}

/// The four verdicts on a received key set against the `(epoch, digest)` a peer persisted, and
/// the refusal of a higher epoch no valid binding authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Continuity {
    /// A higher epoch with a valid ring binding: persist it.
    Accept,
    /// The same epoch and the same digest: what was already held.
    Retry,
    /// The same epoch and another digest: the ring said two things.
    Equivocation,
    /// A lower epoch: an old set presented as current.
    Rollback,
    /// A higher epoch without a valid binding: a public endpoint alone never creates trust.
    Unbound,
}

impl Continuity {
    /// Whether the set may be used.
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Accept | Self::Retry)
    }
}

/// The verdict on a set received at `(epoch, digest)`, `bound` when its ring binding verified,
/// against the `(epoch, digest)` persisted, if any.
pub fn continuity(
    persisted: Option<(u64, [u8; 32])>,
    epoch: u64,
    digest: &[u8; 32],
    bound: bool,
) -> Continuity {
    match persisted {
        Some((held, _)) if epoch < held => Continuity::Rollback,
        Some((held, held_digest)) if epoch == held => {
            if held_digest == *digest {
                Continuity::Retry
            } else {
                Continuity::Equivocation
            }
        }
        _ if bound => Continuity::Accept,
        _ => Continuity::Unbound,
    }
}

/// Verifies a ring binding under the identity key `(suite, public_key)` of `host_id`, for `ring`
/// at `now`, and answers what it binds: a binding for another Host or ring, outside its validity
/// or under another key is refused.
pub fn verify_binding(
    envelope: &[u8],
    identity_suite: Suite,
    identity_public_key: &[u8],
    host_id: &[u8; 16],
    ring: &str,
    now: u64,
) -> Result<Binding, String> {
    if envelope.len() > MAX_BINDING_ENVELOPE_BYTES {
        return Err(format!(
            "a ring binding envelope takes at most {MAX_BINDING_ENVELOPE_BYTES} bytes"
        ));
    }
    let sign1 = Sign1::decode(envelope).map_err(|error| error.to_string())?;
    let payload = sign1
        .verify(
            identity_suite,
            identity_public_key,
            permguard_core::domains::protected::HOST_RING_BINDING,
        )
        .map_err(|error| error.to_string())?;
    let binding = Binding::decode(payload).map_err(|error| error.to_string())?;
    if binding.host_id != *host_id {
        return Err("the binding names another Host".to_owned());
    }
    if binding.ring != ring {
        return Err(format!(
            "the binding names `{}`, not `{ring}`",
            binding.ring
        ));
    }
    if now < binding.not_before || now >= binding.not_after {
        return Err("the binding is outside its validity".to_owned());
    }
    Ok(binding)
}

/// A ring's public statement: what `GET /host/v1/keys/{ring}` serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub ring: String,
    pub epoch: u64,
    pub suite: Suite,
    pub key_set_digest: [u8; 32],
    /// The published set: prepublished, active and retired-public keys.
    pub keys: Vec<Jwk>,
    /// The binding's COSE_Sign1 bytes, once the identity signed one for this epoch.
    pub binding: Option<Vec<u8>>,
}

/// What an operator's transition produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// The ring epoch once it applied.
    pub epoch: u64,
    /// The key it concerned: the key prepublished by a rotation, the key revoked.
    pub kid: String,
}

/// The ring's state, as the journal builds it.
#[derive(Debug, Clone, Default)]
struct Materialized {
    seq: u64,
    epoch: u64,
    suite: Option<Suite>,
    keys: Vec<KeyView>,
    destroyed: BTreeSet<String>,
    /// `(operation id, epoch, target, kid)` of every entry an operator's mutation made.
    operations: Vec<([u8; 16], u64, String, String)>,
}

impl Materialized {
    fn key(&self, kid: &str) -> Option<&KeyView> {
        self.keys.iter().find(|key| key.kid == kid)
    }

    fn active(&self) -> Option<&KeyView> {
        self.keys.iter().find(|key| key.state == State::Active)
    }

    fn prepublished(&self) -> Option<&KeyView> {
        self.keys
            .iter()
            .filter(|key| key.state == State::Prepublished)
            .min_by_key(|key| key.prepublished_at)
    }

    fn published(&self) -> impl Iterator<Item = &KeyView> {
        self.keys.iter().filter(|key| key.state.is_published())
    }

    /// Applies one entry, refusing one the ring's history does not allow.
    fn apply(&mut self, ring: &str, entry: &Entry) -> Result<(), String> {
        if entry.seq != self.seq.saturating_add(1) {
            return Err(format!(
                "entry {} follows {}: the journal has a gap",
                entry.seq, self.seq
            ));
        }
        let position = self.keys.iter().position(|key| key.kid == entry.kid);
        let mut epoch = self.epoch;
        let state = position.map(|at| self.keys[at].state);
        let wrong = |what: &str| {
            Err(format!(
                "`{}` is {what} and cannot be {}",
                entry.kid,
                entry.kind.as_str()
            ))
        };
        match entry.kind {
            Kind::Prepublished => {
                if position.is_some() {
                    return Err(format!("`{}` is prepublished twice", entry.kid));
                }
                let text = entry.jwk.as_deref().unwrap_or_default();
                let jwk: Jwk = serde_json::from_str(text)
                    .map_err(|error| format!("the jwk of `{}`: {error}", entry.kid))?;
                let named = thumbprint::split_kid(&entry.kid);
                if jwk.kid != entry.kid
                    || named.map(|(owner, _)| owner) != Some(ring)
                    || thumbprint::jwk_thumbprint_of(&jwk).as_deref()
                        != named.map(|(_, thumbprint)| thumbprint)
                {
                    return Err(format!(
                        "`{}` is not `{ring}:` and the thumbprint of the key it names",
                        entry.kid
                    ));
                }
                let suite = suite_of(&jwk)
                    .ok_or_else(|| format!("`{}` is of no suite of this profile", entry.kid))?;
                if self.suite.is_some_and(|held| held != suite) {
                    return Err(format!(
                        "`{}` is of another suite than the ring's: a suite transition is explicit",
                        entry.kid
                    ));
                }
                self.suite = Some(suite);
                epoch = epoch.saturating_add(1);
                self.keys.push(KeyView {
                    kid: entry.kid.clone(),
                    state: State::Prepublished,
                    jwk: text.to_owned(),
                    prepublished_at: entry.at,
                    activated_at: None,
                    retired_at: None,
                    revoked_at: None,
                });
            }
            Kind::Activated => {
                if state != Some(State::Prepublished) {
                    return wrong("not prepublished");
                }
                if self.active().is_some() {
                    return Err(format!(
                        "`{}` activated while another key is active",
                        entry.kid
                    ));
                }
                let key = &mut self.keys[position.unwrap_or_default()];
                key.state = State::Active;
                key.activated_at = Some(entry.at);
            }
            Kind::Retired => {
                if state != Some(State::Active) {
                    return wrong("not active");
                }
                let key = &mut self.keys[position.unwrap_or_default()];
                key.state = State::RetiredPublic;
                key.retired_at = Some(entry.at);
            }
            Kind::Revoked => {
                match state {
                    Some(State::Prepublished | State::Active | State::RetiredPublic) => {
                        epoch = epoch.saturating_add(1);
                    }
                    Some(State::Archived) => {}
                    _ => return wrong("revoked already or unknown"),
                }
                let key = &mut self.keys[position.unwrap_or_default()];
                key.state = State::Revoked;
                key.revoked_at = Some(entry.at);
            }
            Kind::Archived => {
                if state != Some(State::RetiredPublic) {
                    return wrong("not retired");
                }
                epoch = epoch.saturating_add(1);
                self.keys[position.unwrap_or_default()].state = State::Archived;
            }
            Kind::Destroyed => {
                if !matches!(
                    state,
                    Some(State::RetiredPublic | State::Revoked | State::Archived)
                ) || !self.destroyed.insert(entry.kid.clone())
                {
                    return wrong("still in use or destroyed already");
                }
            }
            Kind::Sealed | Kind::Rewrapped => {
                if position.is_none() || self.destroyed.contains(&entry.kid) {
                    return wrong("unknown or destroyed");
                }
            }
            Kind::Bound => {
                if thumbprint::split_kid(&entry.kid).map(|(owner, _)| owner) != Some(HOST_IDENTITY)
                {
                    return Err(format!(
                        "a binding is signed by a `{HOST_IDENTITY}` key, not `{}`",
                        entry.kid
                    ));
                }
            }
        }
        if entry.epoch != epoch {
            return Err(format!(
                "entry {} names epoch {} where the ring is at {epoch}",
                entry.seq, entry.epoch
            ));
        }
        self.epoch = epoch;
        self.seq = entry.seq;
        if let Some(id) = entry.operation_id {
            let target = match entry.kind {
                Kind::Prepublished => format!("{ring}:epoch:{epoch}"),
                _ => entry.kid.clone(),
            };
            self.operations.push((id, epoch, target, entry.kid.clone()));
        }
        Ok(())
    }

    fn statement(&self, ring: &str) -> Result<(Suite, [u8; 32], Vec<Jwk>), RingError> {
        let suite = self
            .suite
            .ok_or_else(|| RingError::NotReady(format!("the ring `{ring}` holds no key yet")))?;
        let mut keys = Vec::new();
        let mut thumbprints = Vec::new();
        for key in self.published() {
            let jwk: Jwk = serde_json::from_str(&key.jwk).map_err(|error| {
                RingError::Corrupt(format!("the jwk of `{}`: {error}", key.kid))
            })?;
            keys.push(jwk);
            thumbprints.push(thumbprint_of(&key.kid)?);
        }
        if keys.is_empty() {
            return Err(RingError::NotReady(format!(
                "the ring `{ring}` publishes no key"
            )));
        }
        let refs: Vec<&str> = thumbprints.iter().map(String::as_str).collect();
        let digest = KeySet::new(ring, self.epoch, suite, &refs)
            .and_then(|set| set.digest())
            .map_err(|error| RingError::Corrupt(error.to_string()))?;
        Ok((suite, digest, keys))
    }
}

fn suite_of(jwk: &Jwk) -> Option<Suite> {
    match (jwk.kty.as_str(), jwk.crv.as_deref(), jwk.alg.as_str()) {
        ("OKP", Some("Ed25519"), "EdDSA") => Some(Suite::Ed25519Sha256V1),
        ("EC", Some("P-256"), "ES256") => Some(Suite::P256Sha256V1),
        _ => None,
    }
}

/// The JOSE `alg` a signature of `suite` names.
pub fn jose_alg(suite: Suite) -> &'static str {
    match suite {
        Suite::Ed25519Sha256V1 => "EdDSA",
        Suite::P256Sha256V1 => "ES256",
    }
}

/// The JWK of `public` published as `kid`.
pub fn jwk_of(kid: &str, public: &PublicKey) -> Jwk {
    match public.suite {
        Suite::Ed25519Sha256V1 => Jwk::okp(kid, "Ed25519", "EdDSA", B64.encode(&public.bytes)),
        Suite::P256Sha256V1 => {
            let point = public.bytes.get(1..65).unwrap_or_default();
            Jwk::ec(
                kid,
                "P-256",
                "ES256",
                B64.encode(point.get(..32).unwrap_or_default()),
                B64.encode(point.get(32..).unwrap_or_default()),
            )
        }
    }
}

fn thumbprint_of(kid: &str) -> Result<String, RingError> {
    thumbprint::split_kid(kid)
        .map(|(_, thumbprint)| thumbprint.to_owned())
        .ok_or_else(|| RingError::Corrupt(format!("`{kid}` is not `<ring>:<thumbprint>`")))
}

/// One of the Host's signing rings.
pub struct Ring {
    id: &'static str,
    suite: Suite,
    policy: Policy,
    dir: Dir,
    public: Dir,
    provider: Arc<dyn KeyProvider>,
    time: Arc<TimeGuard>,
    binder: Option<Arc<dyn Binder>>,
    recorder: Option<Arc<dyn Recorder>>,
    /// The state; a signing holds it read, so a retirement taking it to write waits for the
    /// signings in flight before the private half is destroyed.
    state: RwLock<Materialized>,
    /// The binding of the current set, with what it binds.
    binding: RwLock<Option<(Binding, Vec<u8>)>>,
    /// Serializes maintenance and the operator's transitions.
    serial: Mutex<()>,
    /// Set when a journal write failed: what reached the file is uncertain, so the ring takes no
    /// transition until it is opened again and the journal is read back.
    stopped: AtomicBool,
}

impl fmt::Debug for Ring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ring")
            .field("id", &self.id)
            .field("suite", &self.suite)
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

/// The directory of `ring` below `volume`, created when absent.
pub fn directory(volume: &Volume, ring: &str) -> Result<Dir, StorageError> {
    volume.host().subdir(DIRECTORY, true)?.subdir(ring, true)
}

impl Ring {
    /// Opens `ring` on `volume`: the journal replayed and checked, `ring.cbor` rebuilt when
    /// absent or stale. A prepublished or active key whose private half is gone refuses the
    /// open: a lost key is never silently replaced. What a crash left otherwise (a private half a
    /// retirement left, a key generated and never journaled) the first maintenance completes,
    /// journaled and recorded like any transition.
    pub fn open(
        volume: &Volume,
        ring: &'static str,
        suite: Suite,
        policy: Policy,
        time: Arc<TimeGuard>,
    ) -> Result<Self, RingError> {
        if !REGISTERED.contains(&ring) || ring == HOST_IDENTITY {
            return Err(RingError::Refused(format!(
                "`{ring}` is not a ring with keys of its own"
            )));
        }
        let dir = directory(volume, ring)?;
        let public = dir.subdir(PUBLIC, true)?;
        let private = dir.subdir(PRIVATE, true)?;
        let provider: Arc<dyn KeyProvider> = Arc::new(FileKeyProvider::new(private));
        Self::open_with(dir, public, provider, ring, suite, policy, time)
    }

    /// Opens over a provider of the caller's: a custody provider (WP-3.2), a test.
    pub fn open_with(
        dir: Dir,
        public: Dir,
        provider: Arc<dyn KeyProvider>,
        ring: &'static str,
        suite: Suite,
        policy: Policy,
        time: Arc<TimeGuard>,
    ) -> Result<Self, RingError> {
        let opened = Self::open_unchecked(dir, public, provider, ring, suite, policy, time)?;
        opened.check_held()?;
        Ok(opened)
    }

    /// Opens without checking the keys the provider holds: the custody journals what it is
    /// about to do before it does it, then [`Ring::check_held`] runs (WP-3.2).
    pub(crate) fn open_unchecked(
        dir: Dir,
        public: Dir,
        provider: Arc<dyn KeyProvider>,
        ring: &'static str,
        suite: Suite,
        policy: Policy,
        time: Arc<TimeGuard>,
    ) -> Result<Self, RingError> {
        let journal = sequence::recover(&dir, JOURNAL, MAX_ENTRY_BYTES)?;
        let mut state = Materialized::default();
        for item in journal.items {
            let entry = Entry::decode(item)?;
            state
                .apply(ring, &entry)
                .map_err(|detail| RingError::Corrupt(format!("{}: {detail}", ring)))?;
        }
        if let Some(held) = state.suite
            && held != suite
        {
            return Err(RingError::Refused(format!(
                "the ring `{ring}` signs with {held} and the configuration asks {suite}: a suite \
                 transition is explicit, and this build makes none"
            )));
        }
        let binding = match read_view(&dir, BINDING, format::VIEW)? {
            Some(bytes) => Sign1::decode(&bytes)
                .ok()
                .and_then(|sign1| Binding::decode(sign1.payload_unverified()).ok())
                .map(|binding| (binding, bytes)),
            None => None,
        };
        let opened = Self {
            id: ring,
            suite,
            policy,
            dir,
            public,
            provider,
            time,
            binder: None,
            recorder: None,
            state: RwLock::new(state),
            binding: RwLock::new(binding),
            serial: Mutex::new(()),
            stopped: AtomicBool::new(false),
        };
        Ok(opened)
    }

    /// Signs the ring's bindings with `binder`.
    pub fn with_binder(mut self, binder: Arc<dyn Binder>) -> Self {
        self.binder = Some(binder);
        self
    }

    /// Records every transition in `recorder` too.
    pub fn with_recorder(mut self, recorder: Arc<dyn Recorder>) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// The ring's registered name.
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// The ring's suite.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The ring epoch: `0` before its first key.
    pub fn epoch(&self) -> u64 {
        self.read().epoch
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Materialized> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Materialized> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The materialized view of the journal.
    pub fn view(&self) -> Result<View, RingError> {
        let state = self.read();
        let (suite, key_set_digest) = match state.statement(self.id) {
            Ok((suite, digest, _)) => (suite, digest),
            Err(RingError::NotReady(_)) => (self.suite, [0; 32]),
            Err(error) => return Err(error),
        };
        Ok(View {
            ring: self.id.to_owned(),
            suite,
            epoch: state.epoch,
            key_set_digest,
            keys: state.keys.clone(),
        })
    }

    /// The public statement: the published set, its epoch and digest, and the binding of this
    /// epoch when the identity signed one.
    pub fn statement(&self) -> Result<Statement, RingError> {
        let state = self.read();
        let (suite, key_set_digest, keys) = state.statement(self.id)?;
        let binding = self
            .binding
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|(binding, _)| {
                binding.epoch == state.epoch && binding.key_set_digest == key_set_digest
            })
            .map(|(_, bytes)| bytes.clone());
        Ok(Statement {
            ring: self.id.to_owned(),
            epoch: state.epoch,
            suite,
            key_set_digest,
            keys,
            binding,
        })
    }

    /// What the journal shows of `operation_id`: the epoch it left the ring at and its target.
    pub fn observe(&self, operation_id: &OperationId) -> Option<Observed> {
        self.read()
            .operations
            .iter()
            .find(|(id, _, _, _)| id == operation_id.as_bytes())
            .map(|(_, epoch, target, _)| Observed {
                revision: *epoch,
                target: Some(target.clone()),
            })
    }

    /// The key an operator's mutation concerned: the key a rotation prepublished, the key a
    /// revocation revoked.
    pub fn operation_kid(&self, operation_id: &OperationId) -> Option<String> {
        self.read()
            .operations
            .iter()
            .find(|(id, _, _, _)| id == operation_id.as_bytes())
            .map(|(_, _, _, kid)| kid.clone())
    }

    /// Appends `entry` to the journal, then applies it: the journal is written before the
    /// change shows anywhere.
    fn commit(&self, entry: Entry) -> Result<Entry, RingError> {
        let mut committed = self.commit_all(vec![entry])?;
        committed
            .pop()
            .ok_or_else(|| RingError::Corrupt("an empty commit".to_owned()))
    }

    /// Appends `entries` to the journal, then applies them under one write guard: a hand-over's
    /// retirement and activation show together, and no signing sees the ring between them.
    fn commit_all(&self, entries: Vec<Entry>) -> Result<Vec<Entry>, RingError> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err(RingError::NotReady(format!(
                "the journal of the ring `{}` failed a write: it takes no transition until the \
                 next start reads it back",
                self.id
            )));
        }
        let mut encoded = Vec::with_capacity(entries.len());
        {
            // Checked before anything is written: an entry the history refuses never lands.
            let mut probe = self.read().clone();
            for entry in &entries {
                encoded.push(entry.encode()?);
                probe
                    .apply(self.id, entry)
                    .map_err(|detail| RingError::Refused(format!("{}: {detail}", self.id)))?;
            }
        }
        for bytes in &encoded {
            if let Err(error) = sequence::append(&self.dir, JOURNAL, bytes) {
                self.stopped.store(true, Ordering::SeqCst);
                return Err(error.into());
            }
        }
        {
            let mut state = self.write();
            for entry in &entries {
                state
                    .apply(self.id, entry)
                    .map_err(|detail| RingError::Corrupt(format!("{}: {detail}", self.id)))?;
            }
        }
        if let Some(recorder) = &self.recorder {
            for entry in &entries {
                recorder.record(self.id, entry);
            }
        }
        Ok(entries)
    }

    /// The entry that follows `previous`, for a transition of several entries.
    fn following(previous: &Entry, kind: Kind, kid: &str, epoch_step: u64, at: u64) -> Entry {
        Entry {
            seq: previous.seq.saturating_add(1),
            kind,
            kid: kid.to_owned(),
            epoch: previous.epoch.saturating_add(epoch_step),
            at,
            operation_id: None,
            reason: None,
            jwk: None,
            compromised_at: None,
        }
    }

    fn entry(&self, kind: Kind, kid: &str, epoch_step: u64, at: u64) -> Entry {
        let state = self.read();
        Entry {
            seq: state.seq.saturating_add(1),
            kind,
            kid: kid.to_owned(),
            epoch: state.epoch.saturating_add(epoch_step),
            at,
            operation_id: None,
            reason: None,
            jwk: None,
            compromised_at: None,
        }
    }

    /// Generates a key and prepublishes it: the private half through the provider, the public
    /// half in `public/`, then the journal entry.
    fn prepublish(&self, at: u64, operation: Option<[u8; 16]>) -> Result<Entry, RingError> {
        let entry = self.prepare(self.entry(Kind::Prepublished, "", 1, at), operation)?;
        self.commit(entry)
    }

    /// Generates a key and writes its public half, answering the `prepublished` entry `template`
    /// becomes for it: nothing is journaled yet, and a key never journaled is destroyed by the
    /// next maintenance.
    fn prepare(&self, template: Entry, operation: Option<[u8; 16]>) -> Result<Entry, RingError> {
        let (slot, public) = self.provider.generate_addressed(self.suite)?;
        let kid = thumbprint::kid(self.id, &slot);
        let jwk = serde_json::to_string(&jwk_of(&kid, &public))
            .map_err(|error| RingError::Corrupt(error.to_string()))?;
        self.publish_public(&slot, &jwk)?;
        Ok(Entry {
            kind: Kind::Prepublished,
            kid,
            operation_id: operation,
            jwk: Some(jwk),
            ..template
        })
    }

    fn publish_public(&self, thumbprint: &str, jwk: &str) -> Result<(), RingError> {
        let name = format!("{thumbprint}.jwk");
        let readable = |bytes: &[u8]| serde_json::from_slice::<Jwk>(bytes).is_ok();
        let same = |bytes: &[u8]| bytes == jwk.as_bytes();
        match publish_immutable(&self.public, &name, jwk.as_bytes(), &readable, &same)? {
            Published::Written | Published::AlreadyThere => Ok(()),
        }
    }

    /// Destroys the private half of `kid`, after the signings in flight: taking the state to
    /// write waits for every signing that read it.
    fn destroy(&self, kid: &str, at: u64) -> Result<(), RingError> {
        drop(self.write());
        self.provider.destroy(&thumbprint_of(kid)?)?;
        self.commit(self.entry(Kind::Destroyed, kid, 0, at))?;
        Ok(())
    }

    /// Refuses a ring whose prepublished or active key has lost its private half, or holds
    /// another key than the one it published, and rebuilds `ring.cbor` from the journal. The
    /// provider opens every such key here: a sealed key the KEK does not open, or a remote key the
    /// custody no longer reaches, fails the start rather than the first signature (WP-3.2).
    pub(crate) fn check_held(&self) -> Result<(), RingError> {
        let state = self.read().clone();
        let held: BTreeSet<String> = self.provider.slots()?.into_iter().collect();
        for key in &state.keys {
            if !matches!(key.state, State::Prepublished | State::Active) {
                continue;
            }
            let slot = thumbprint_of(&key.kid)?;
            if !held.contains(&slot) {
                return Err(RingError::Corrupt(format!(
                    "the ring `{}` names `{}` {} and its private half is not held: a lost key is \
                     never replaced silently",
                    self.id,
                    key.kid,
                    key.state.as_str()
                )));
            }
            let published: Jwk = serde_json::from_str(&key.jwk)
                .map_err(|error| RingError::Corrupt(format!("`{}`: {error}", key.kid)))?;
            let opened = jwk_of(&key.kid, &self.provider.public(&slot, self.suite)?);
            if (opened.x.as_str(), opened.y.as_deref())
                != (published.x.as_str(), published.y.as_deref())
            {
                return Err(RingError::Corrupt(format!(
                    "the ring `{}` published `{}` and its custody holds another key under it",
                    self.id, key.kid
                )));
            }
        }
        if !state.keys.is_empty() {
            self.write_view()?;
        }
        Ok(())
    }

    /// Completes what a crash left: a private half not destroyed after its key left signing, a
    /// key generated and never journaled, a public file missing.
    fn complete(&self, now: u64) -> Result<(), RingError> {
        let state = self.read().clone();
        let held: BTreeSet<String> = self.provider.slots()?.into_iter().collect();
        for key in &state.keys {
            let slot = thumbprint_of(&key.kid)?;
            if !matches!(key.state, State::Prepublished | State::Active)
                && !state.destroyed.contains(&key.kid)
            {
                self.destroy(&key.kid, now)?;
            }
            self.publish_public(&slot, &key.jwk)?;
        }
        let named: BTreeSet<String> = state
            .keys
            .iter()
            .filter_map(|key| thumbprint_of(&key.kid).ok())
            .collect();
        for slot in held.difference(&named) {
            // Generated, never journaled: nothing ever named it.
            self.provider.destroy(slot)?;
        }
        Ok(())
    }

    fn write_view(&self) -> Result<(), RingError> {
        let bytes = self.view()?.encode()?;
        if read_view(&self.dir, VIEW, format::VIEW)?.as_deref() != Some(bytes.as_slice()) {
            replace_view(&self.dir, VIEW, format::VIEW, &bytes)?;
        }
        Ok(())
    }

    fn serial(&self) -> std::sync::MutexGuard<'_, ()> {
        self.serial.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One maintenance pass: the first key signs at once; a prepublished key past
    /// `publish_ahead` takes over and its predecessor's private half is destroyed; a successor is
    /// prepublished `publish_ahead` before the active key's turn ends; a retired key past
    /// `retain` is archived; the binding is issued for a new epoch and before it ends.
    pub fn maintain_now(&self) -> Result<Maintenance, RingError> {
        let _serial = self.serial();
        let now = self.time.now_secs();
        let mut report = Maintenance::default();
        let ahead = self.policy.publish_ahead.as_secs();
        self.complete(now)?;

        // No key signs: the first start, or a crash or a failure between a key leaving signing
        // and its successor taking over. The oldest waiting key takes over at once, or a new key
        // is prepublished and activated at once: a ring is never left without an active key.
        let (any, active, waiting) = {
            let state = self.read();
            (
                !state.keys.is_empty(),
                state.active().is_some(),
                state.prepublished().map(|key| key.kid.clone()),
            )
        };
        if !active {
            match waiting {
                Some(kid) => {
                    self.commit(self.entry(Kind::Activated, &kid, 0, now))?;
                }
                None => {
                    let prepublished =
                        self.prepare(self.entry(Kind::Prepublished, "", 1, now), None)?;
                    let activated =
                        Self::following(&prepublished, Kind::Activated, &prepublished.kid, 0, now);
                    self.commit_all(vec![prepublished, activated])?;
                    report.published += 1;
                }
            }
            report.activated += 1;
            if any {
                tracing::warn!(
                    event.name = "host.keys.active_restored",
                    component = "host",
                    ring = self.id,
                    "the ring had no active key; one was activated at once"
                );
            }
        }

        // Every prepublished key whose window has passed takes over, oldest first: a Host that
        // was stopped for a week comes back with the ring correct after one pass.
        loop {
            let (due, active) = {
                let state = self.read();
                let due = state
                    .prepublished()
                    .filter(|key| key.prepublished_at.saturating_add(ahead) <= now)
                    .map(|key| key.kid.clone());
                (due, state.active().map(|key| key.kid.clone()))
            };
            let Some(due) = due else {
                break;
            };
            let activated = match &active {
                Some(active) => {
                    let retired = self.entry(Kind::Retired, active, 0, now);
                    let activated = Self::following(&retired, Kind::Activated, &due, 0, now);
                    report.retired += 1;
                    vec![retired, activated]
                }
                None => vec![self.entry(Kind::Activated, &due, 0, now)],
            };
            self.commit_all(activated)?;
            report.activated += 1;
            if let Some(active) = &active {
                self.destroy(active, now)?;
            }
        }

        let successor_due = {
            let state = self.read();
            state.prepublished().is_none()
                && state
                    .active()
                    .and_then(|key| key.activated_at)
                    .is_some_and(|activated| {
                        activated
                            .saturating_add(self.policy.rotate_every.as_secs())
                            .saturating_sub(ahead)
                            <= now
                    })
        };
        if successor_due {
            self.prepublish(now, None)?;
            report.published += 1;
        }

        let due: Vec<String> = self
            .read()
            .keys
            .iter()
            .filter(|key| key.state == State::RetiredPublic)
            .filter(|key| {
                key.retired_at
                    .is_some_and(|at| at.saturating_add(self.policy.retain.as_secs()) <= now)
            })
            .map(|key| key.kid.clone())
            .collect();
        for kid in due {
            self.commit(self.entry(Kind::Archived, &kid, 1, now))?;
            report.archived += 1;
        }

        self.write_view()?;
        self.bind_if_due(now)?;
        Ok(report)
    }

    /// Issues the binding of the current set when none binds this epoch, or the one held ends
    /// within [`BINDING_RENEWAL`].
    fn bind_if_due(&self, now: u64) -> Result<(), RingError> {
        let Some(binder) = &self.binder else {
            return Ok(());
        };
        let statement = self.statement()?;
        // The binding held counts only when it verifies under the identity key that signs now:
        // a file changed on the volume, or a binding the identity signed before it rotated, is
        // issued again.
        let identity = binder.public_key();
        let current = self
            .binding
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|(binding, bytes)| {
                binding.epoch == statement.epoch
                    && binding.key_set_digest == statement.key_set_digest
                    && binding.not_after > now.saturating_add(BINDING_RENEWAL.as_secs())
                    && verify_binding(
                        bytes,
                        identity.suite,
                        &identity.bytes,
                        &binder.host_id(),
                        self.id,
                        now,
                    )
                    .is_ok_and(|verified| verified == *binding)
            });
        if current {
            return Ok(());
        }
        let binding = Binding {
            host_id: binder.host_id(),
            ring: self.id.to_owned(),
            epoch: statement.epoch,
            key_set_digest: statement.key_set_digest,
            suite: statement.suite,
            not_before: now,
            not_after: now.saturating_add(BINDING_LIFETIME.as_secs()),
        };
        let envelope = binder
            .sign(binding.encode()?)
            .map_err(|detail| RingError::NotReady(format!("signing the binding: {detail}")))?;
        let signer = binder
            .kid()
            .map_err(|detail| RingError::NotReady(format!("the identity's kid: {detail}")))?;
        self.commit(self.entry(Kind::Bound, &signer, 0, now))?;
        replace_view(&self.dir, BINDING, format::VIEW, &envelope)?;
        *self.binding.write().unwrap_or_else(PoisonError::into_inner) = Some((binding, envelope));
        Ok(())
    }

    fn expect_epoch(&self, expected: u64) -> Result<(), RingError> {
        let current = self.epoch();
        if current != expected {
            return Err(RingError::Conflict { expected, current });
        }
        Ok(())
    }

    /// An operator's rotation, inside the mutation that authorized it: a successor is
    /// prepublished now and takes over once `publish_ahead` has passed. Refused while another
    /// successor waits.
    pub fn rotate(
        &self,
        applying: &Applying<'_>,
        expected_epoch: u64,
    ) -> Result<Transition, RingError> {
        let _serial = self.serial();
        self.expect_epoch(expected_epoch)?;
        self.check_rotatable()?;
        let now = self.time.now_secs();
        let entry = self.prepublish(now, Some(*applying.operation_id().as_bytes()))?;
        self.write_view().map_err(|error| {
            RingError::Unfinished(format!(
                "`{}` is prepublished and the rotation did not finish: {error}",
                entry.kid
            ))
        })?;
        self.bind_after_mutation(now);
        Ok(Transition {
            epoch: entry.epoch,
            kid: entry.kid,
        })
    }

    /// Whether a rotation applies now: an active key, and no successor waiting.
    pub fn check_rotatable(&self) -> Result<(), RingError> {
        let state = self.read();
        if state.active().is_none() {
            return Err(RingError::NotReady(format!(
                "the ring `{}` has no active key yet",
                self.id
            )));
        }
        if let Some(waiting) = state.prepublished() {
            return Err(RingError::Pending(format!(
                "`{}` is prepublished already and takes over once publish_ahead has passed",
                waiting.kid
            )));
        }
        Ok(())
    }

    /// Whether `kid` may be revoked: a key of this ring not revoked yet; answers the epoch.
    pub fn check_revocable(&self, kid: &str) -> Result<u64, RingError> {
        let state = self.read();
        match state.key(kid) {
            None => Err(RingError::UnknownKey(format!(
                "the ring `{}` holds no key `{kid}`",
                self.id
            ))),
            Some(key) if key.state == State::Revoked => {
                Err(RingError::Revoked(format!("`{kid}` is revoked already")))
            }
            Some(_) => Ok(state.epoch),
        }
    }

    /// An operator's revocation, inside the mutation that authorized it: the key leaves the
    /// published set at once and its private half is destroyed; an active key is replaced at
    /// once, by the waiting successor or a new key, without the publish-ahead window a compromise
    /// cannot wait for.
    pub fn revoke(
        &self,
        applying: &Applying<'_>,
        kid: &str,
        reason: &str,
        compromised_at: Option<u64>,
        expected_epoch: u64,
    ) -> Result<Transition, RingError> {
        let _serial = self.serial();
        self.expect_epoch(expected_epoch)?;
        self.check_revocable(kid)?;
        if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
            return Err(RingError::Refused(format!(
                "a revocation reason takes 1 to {MAX_REASON_BYTES} bytes"
            )));
        }
        let now = self.time.now_secs();
        let (was, published, destroyed, waiting) = {
            let state = self.read();
            let key = state.key(kid).map(|key| key.state);
            (
                key,
                key.is_some_and(State::is_published),
                state.destroyed.contains(kid),
                state.prepublished().map(|key| key.kid.clone()),
            )
        };
        let revoked = Entry {
            operation_id: Some(*applying.operation_id().as_bytes()),
            reason: Some(reason.to_owned()),
            compromised_at,
            ..self.entry(Kind::Revoked, kid, u64::from(published), now)
        };
        // An active key is replaced in the same commit, by the waiting successor or a key
        // generated now: no signing sees the ring without an active key.
        let mut entries = vec![revoked.clone()];
        if was == Some(State::Active) {
            let successor = match waiting {
                Some(kid) => kid,
                None => {
                    let prepublished = self.prepare(
                        Self::following(&revoked, Kind::Prepublished, "", 1, now),
                        None,
                    )?;
                    let kid = prepublished.kid.clone();
                    entries.push(prepublished);
                    kid
                }
            };
            let last = entries.last().cloned().unwrap_or_else(|| revoked.clone());
            entries.push(Self::following(&last, Kind::Activated, &successor, 0, now));
        }
        self.commit_all(entries)?;
        // From here the revocation is in the journal: a later failure leaves the ring changed,
        // and maintenance finishes it.
        let unfinished = |error: RingError| {
            RingError::Unfinished(format!(
                "`{kid}` is revoked and the revocation did not finish: {error}"
            ))
        };
        // A key that stopped signing earlier was destroyed when it did.
        if !destroyed {
            self.destroy(kid, now).map_err(unfinished)?;
        }
        self.write_view().map_err(unfinished)?;
        self.bind_after_mutation(now);
        Ok(Transition {
            epoch: revoked.epoch,
            kid: kid.to_owned(),
        })
    }

    /// Journals what the custody did to private halves at Bootstrap (WP-3.2): each slot in
    /// `slots`, sealed in place or rewrapped, an entry of `kind`.
    pub fn note_custody(&self, kind: Kind, slots: &[String]) -> Result<(), RingError> {
        let _serial = self.serial();
        let now = self.time.now_secs();
        for slot in slots {
            let kid = thumbprint::kid(self.id, slot);
            // A key the journal never named — generated before a crash, before its entry — is
            // not the ring's yet: the first maintenance completes or removes it.
            let known = {
                let state = self.read();
                state.key(&kid).is_some() && !state.destroyed.contains(&kid)
            };
            if !known {
                continue;
            }
            self.commit(self.entry(kind, &kid, 0, now))?;
        }
        Ok(())
    }

    /// The binding a mutation's new epoch needs: a failure is logged and left to maintenance,
    /// the mutation having applied.
    fn bind_after_mutation(&self, now: u64) {
        if let Err(error) = self.bind_if_due(now) {
            tracing::warn!(
                event.name = "host.keys.binding_deferred",
                component = "host",
                ring = self.id,
                error = %error,
                "the ring binding of a new epoch could not be issued; maintenance retries"
            );
        }
    }
}

impl permguard_core::keys::Sign for Ring {
    fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        self.read()
            .active()
            .map(|key| KeyId::new(key.kid.clone()))
            .ok_or_else(|| {
                permguard_core::KeyError::not_ready(format!(
                    "no key of the ring `{}` is active yet",
                    self.id
                ))
            })
    }

    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
        // Held across the signing: a retirement waits for it before destroying the key.
        let state = self.read();
        let kid = state.active().map(|key| key.kid.clone()).ok_or_else(|| {
            permguard_core::KeyError::not_ready(format!(
                "no key of the ring `{}` is active yet",
                self.id
            ))
        })?;
        let slot = thumbprint_of(&kid).map_err(core_error)?;
        let bytes = self
            .provider
            .sign(&slot, self.suite, payload)
            .map_err(|error| core_error(RingError::Provider(error)))?;
        drop(state);
        Ok(Signature::new(KeyId::new(kid), jose_alg(self.suite), bytes))
    }
}

impl permguard_core::keys::PublicSet for Ring {
    /// The published set; never an empty one: a ring with no key is not ready.
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        self.read()
            .statement(self.id)
            .map(|(_, _, keys)| keys)
            .map_err(core_error)
    }
}

impl permguard_core::KeyManager for Ring {
    fn name(&self) -> &'static str {
        "host-ring"
    }

    fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
        self.maintain_now().map_err(core_error)
    }
}

/// The rings, as the mutation engine asks them about an operation: the domain [`DOMAIN`],
/// recovered at open (WP-3.6).
pub struct Rings<'a>(pub &'a [Arc<Ring>]);

impl Domain for Rings<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, _target: Option<&str>) -> Option<Observed> {
        self.0.iter().find_map(|ring| ring.observe(operation_id))
    }
}

/// The CBOR of a key-set statement and its digest, for a ring's tests and vectors.
pub fn key_set_digest(
    ring: &str,
    epoch: u64,
    suite: Suite,
    thumbprints: &[&str],
) -> Result<[u8; 32], String> {
    thumbprint::key_set_digest(ring, epoch, suite, thumbprints).map_err(|error| error.to_string())
}

/// Whether `entries` are a history the ring `ring` allows: what a migration checks before it
/// writes a journal.
pub fn check_history(ring: &str, entries: &[Entry]) -> Result<(), String> {
    let mut state = Materialized::default();
    for entry in entries {
        state.apply(ring, entry)?;
    }
    if state.active().is_none() {
        return Err(format!("the ring `{ring}` would have no active key"));
    }
    Ok(())
}

/// The stored public keys of a ring, `public/<thumbprint>.jwk` below `public`: what a sealed
/// private half must open as (WP-3.2).
pub fn stored_public(public: Dir) -> super::custody::StoredPublic {
    Box::new(move |slot, suite| {
        let Some(bytes) = public.read(&format!("{slot}.jwk"))? else {
            return Ok(None);
        };
        let jwk: Jwk = serde_json::from_slice(&bytes)
            .map_err(|error| ProviderError::Malformed(format!("`{slot}.jwk`: {error}")))?;
        let decode = |text: &str| {
            B64.decode(text)
                .map_err(|error| ProviderError::Malformed(format!("`{slot}.jwk`: {error}")))
        };
        let mut public = decode(&jwk.x)?;
        if let Some(y) = jwk.y.as_deref() {
            public.insert(0, 0x04);
            public.extend(decode(y)?);
        }
        // The file is named by its key's thumbprint: one copied over another slot's is refused.
        let key = PublicKey {
            suite,
            bytes: public,
        };
        if super::thumbprint_of(&key)? != slot {
            return Err(ProviderError::Malformed(format!(
                "`{slot}.jwk` holds another key than its name"
            )));
        }
        Ok(Some(key.bytes))
    })
}

/// Decodes `journal.cborseq`'s entries, for the tests and an offline reader.
pub fn journal_entries(dir: &Dir) -> Result<Vec<Entry>, RingError> {
    let journal = sequence::read(dir, JOURNAL, MAX_ENTRY_BYTES)?;
    journal
        .items
        .into_iter()
        .map(|item| Entry::decode(item).map_err(RingError::Record))
        .collect()
}

#[cfg(test)]
mod tests;
