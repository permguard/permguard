// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's composition core: one implementation of every generic capability, and the typed,
//! least-privilege handles a Plane receives for what it declared (P1).
//!
//! ```text
//! composition (permguard-server)
//!   ─▶ Host::builder()          the rings, the audit recorder, the secret store: built once
//!   ─▶ host.register(declaration)   per Plane, before its state opens; collisions refused
//!   ─▶ Registration              the Plane's handles, limited to what it declared
//! ```
//!
//! | Handle             | What a Plane can do with it                     | What it cannot reach                     |
//! | ------------------ | ----------------------------------------------- | ---------------------------------------- |
//! | [`Signer<T>`]      | sign with the ring artifact `T` names           | the key manager, another ring, any key   |
//! | [`PublicKeys`]     | read a declared ring's public set               | signing                                  |
//! | [`AuditHandle<T>`] | record the actions schema `T` declares          | another action, the sink, the trail      |
//! | [`SecretHandle<T>`]| an HMAC under the secret of purpose `T`         | the secret's bytes                       |
//! | [`StreamProducer`], [`TaskClient`], [`Authorization`] | declared now; built by their packages | — |
//!
//! Least privilege is a property of the types: no handle has an accessor that returns the key
//! manager, the secret's bytes or a Host-private path, so a Plane holding one cannot widen it. A
//! Plane is trusted code in this process, and the handles are not a sandbox; they keep a Plane from
//! signing, recording or reading what it did not declare by mistake — the confused-deputy risk the
//! security architecture names.
//!
//! `StreamProducer`, `TaskClient` and `Authorization` are declared today, and their collisions are
//! refused at startup, but no Plane can build one yet: the stream engine (WP-5.1), task routing
//! (WP-4.x) and the authorization model (WP-2.4) build them when they land.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
#[cfg(test)]
use permguard_core::keys::Sign as _;
use permguard_core::keys::{Jwk, KeyId, KeyManager, Signature};
use permguard_core::secrets::{SecretRef, SecretStore};
use permguard_core::server::AuditRecorder;
use permguard_core::{AuditError, Subject};
use sha2::Sha256;
use zeroize::Zeroizing;

/// A key ring the Host holds, by its registered name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RingId(&'static str);

impl RingId {
    /// The ring's registered name.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// The ring the Control Plane signs what it serves with.
pub const CONTROL_ATTEST: RingId = RingId("control.attest");
/// The ring the Data Plane signs its evidence with.
pub const DATA_ATTEST: RingId = RingId("data.attest");
/// The Host's own operations ring: it seals the audit trail, and no Plane is handed it.
pub const HOST_OPERATIONS: RingId = RingId("host.operations");

/// An artifact a Plane may sign: its protected type and the ring that signs it.
pub trait Artifact: 'static {
    /// The protected type, or content type, the artifact is signed as.
    const TYPE: &'static str;
    /// The ring that signs it.
    const RING: RingId;
}

/// Today's signed NOTP head statement, signed by the Control Plane.
pub struct HeadStatementV1;

impl Artifact for HeadStatementV1 {
    const TYPE: &'static str = permguard_core::domains::protected::NOTP_HEAD;
    const RING: RingId = CONTROL_ATTEST;
}

/// A decision batch, signed by the Data Plane that decided.
pub struct DecisionBatchV1;

impl Artifact for DecisionBatchV1 {
    const TYPE: &'static str = permguard_core::domains::protected::DECISION_BATCH;
    const RING: RingId = DATA_ATTEST;
}

/// An event batch, signed by the Data Plane that recorded the history.
pub struct EventBatchV1;

impl Artifact for EventBatchV1 {
    const TYPE: &'static str = permguard_core::domains::protected::EVENT_BATCH;
    const RING: RingId = DATA_ATTEST;
}

/// The actions an audit schema lets its holder record.
pub trait AuditSchema: 'static {
    /// The schema's name, unique across Planes.
    const NAME: &'static str;
    /// Every action the holder may record.
    const ACTIONS: &'static [&'static str];
}

/// The purpose a secret serves; a secret is resolved for one purpose and used for no other.
pub trait SecretPurpose: 'static {
    /// The purpose's name, unique across Planes.
    const NAME: &'static str;
    /// The shortest secret this purpose accepts.
    const MIN_BYTES: usize;
}

/// What a Plane declares before its state opens.
#[derive(Debug, Clone, Default)]
pub struct Declaration {
    plane: String,
    signers: Vec<(&'static str, RingId)>,
    public_rings: Vec<RingId>,
    audit: Vec<(&'static str, &'static [&'static str])>,
    secrets: Vec<(&'static str, SecretRef, String, usize)>,
    streams: Vec<String>,
    tasks: Vec<String>,
    scope_schemas: Vec<String>,
}

impl Declaration {
    /// A declaration for the Plane `plane`.
    pub fn new(plane: impl Into<String>) -> Self {
        Self {
            plane: plane.into(),
            ..Self::default()
        }
    }

    /// Declares that this Plane signs artifact `T`, with the ring `T` names.
    pub fn signs<T: Artifact>(mut self) -> Self {
        self.signers.push((T::TYPE, T::RING));
        self
    }

    /// Declares that this Plane reads the public set of `ring`, to publish it or verify with it.
    pub fn reads_public_keys(mut self, ring: RingId) -> Self {
        self.public_rings.push(ring);
        self
    }

    /// Declares the audit schema `T`.
    pub fn audits<T: AuditSchema>(mut self) -> Self {
        self.audit.push((T::NAME, T::ACTIONS));
        self
    }

    /// Declares the secret of purpose `T`, resolved from `reference` at version `version`.
    pub fn uses_secret<T: SecretPurpose>(
        mut self,
        reference: SecretRef,
        version: impl Into<String>,
    ) -> Self {
        self.secrets
            .push((T::NAME, reference, version.into(), T::MIN_BYTES));
        self
    }

    /// Declares a stream descriptor this Plane produces.
    pub fn produces_stream(mut self, descriptor: impl Into<String>) -> Self {
        self.streams.push(descriptor.into());
        self
    }

    /// Declares a task type this Plane handles.
    pub fn handles_task(mut self, task: impl Into<String>) -> Self {
        self.tasks.push(task.into());
        self
    }

    /// Declares a resource scope schema this Plane owns.
    pub fn owns_scope_schema(mut self, schema: impl Into<String>) -> Self {
        self.scope_schemas.push(schema.into());
        self
    }

    /// The Plane this declaration is for.
    pub fn plane(&self) -> &str {
        &self.plane
    }
}

/// Why composition refused a declaration or a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionError {
    /// Two declarations claim one thing: a ring's artifact type, an audit schema, a secret purpose,
    /// a stream descriptor, a task type or a scope schema.
    Collision {
        what: &'static str,
        name: String,
        first: String,
        second: String,
    },
    /// A Plane registered twice.
    AlreadyRegistered(String),
    /// A handle asked for something its Plane did not declare.
    Undeclared { plane: String, what: String },
    /// A declared secret could not be resolved, or is too short for its purpose.
    Secret {
        purpose: &'static str,
        detail: String,
    },
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Collision {
                what,
                name,
                first,
                second,
            } => write!(
                f,
                "the {what} `{name}` is declared by both `{first}` and `{second}`; each is \
                 declared once"
            ),
            Self::AlreadyRegistered(plane) => write!(f, "the plane `{plane}` registered twice"),
            Self::Undeclared { plane, what } => write!(
                f,
                "the plane `{plane}` asked for {what}, which it did not declare"
            ),
            Self::Secret { purpose, detail } => {
                write!(f, "the secret for `{purpose}`: {detail}")
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// The Host: every generic capability, implemented once.
pub struct Host {
    rings: BTreeMap<RingId, Arc<dyn KeyManager>>,
    recorder: Option<AuditRecorder>,
    claimed: std::sync::Mutex<Claims>,
}

#[derive(Default)]
struct Claims {
    planes: Vec<String>,
    by_kind: BTreeMap<(&'static str, String), String>,
}

/// Builds the [`Host`] from the collaborators composition resolved.
#[derive(Default)]
pub struct HostBuilder {
    rings: BTreeMap<RingId, Arc<dyn KeyManager>>,
    recorder: Option<AuditRecorder>,
}

impl HostBuilder {
    /// The key manager behind `ring`.
    pub fn ring(mut self, ring: RingId, keys: Arc<dyn KeyManager>) -> Self {
        self.rings.insert(ring, keys);
        self
    }

    /// The audit recorder every Plane's records go through.
    pub fn audit(mut self, recorder: AuditRecorder) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// The Host.
    pub fn build(self) -> Host {
        Host {
            rings: self.rings,
            recorder: self.recorder,
            claimed: std::sync::Mutex::new(Claims::default()),
        }
    }
}

impl Host {
    /// A builder; only a composition root calls it.
    pub fn builder() -> HostBuilder {
        HostBuilder::default()
    }

    /// Registers a Plane's declaration and answers its handles; its declared secrets are resolved
    /// from `secrets`, here and only here.
    ///
    /// Refuses a Plane registered before, and any declaration that collides with one already
    /// registered: an artifact type, a ring signed by two Planes, an audit schema, a secret purpose,
    /// a stream descriptor, a task type or a scope schema. Declared secrets are resolved here, so a
    /// missing or short one stops the start rather than the first request.
    pub fn register(
        &self,
        declaration: Declaration,
        secrets: Option<&dyn SecretStore>,
    ) -> Result<Registration, CompositionError> {
        let plane = declaration.plane.clone();
        // Secrets first, outside the lock: a declaration whose secret does not resolve leaves no
        // claim behind, so nothing it named is held by a plane that never registered.
        let store = secrets;
        let mut secrets = BTreeMap::new();
        for (purpose, reference, version, min_bytes) in &declaration.secrets {
            let store = store.ok_or(CompositionError::Secret {
                purpose,
                detail: "no secret store is composed".to_owned(),
            })?;
            let secret = store
                .resolve(reference)
                .map_err(|error| CompositionError::Secret {
                    purpose,
                    detail: format!("`{}` does not resolve: {error}", reference.name()),
                })?;
            if secret.expose().len() < *min_bytes {
                return Err(CompositionError::Secret {
                    purpose,
                    detail: format!(
                        "`{}` is shorter than the {min_bytes} bytes the purpose requires",
                        reference.name()
                    ),
                });
            }
            secrets.insert(
                *purpose,
                (
                    Arc::new(Zeroizing::new(secret.expose().to_vec())),
                    version.clone(),
                ),
            );
        }

        {
            let mut claims = self
                .claimed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if claims.planes.contains(&plane) {
                return Err(CompositionError::AlreadyRegistered(plane));
            }
            let mut claimed: Vec<(&'static str, String)> = Vec::new();
            for (artifact, ring) in &declaration.signers {
                claimed.push(("artifact type", (*artifact).to_owned()));
                claimed.push(("signing ring", ring.as_str().to_owned()));
            }
            claimed.extend(
                declaration
                    .audit
                    .iter()
                    .map(|(name, _)| ("audit schema", (*name).to_owned())),
            );
            claimed.extend(
                declaration
                    .secrets
                    .iter()
                    .map(|(purpose, ..)| ("secret purpose", (*purpose).to_owned())),
            );
            claimed.extend(
                declaration
                    .streams
                    .iter()
                    .map(|name| ("stream descriptor", name.clone())),
            );
            claimed.extend(
                declaration
                    .tasks
                    .iter()
                    .map(|name| ("task type", name.clone())),
            );
            claimed.extend(
                declaration
                    .scope_schemas
                    .iter()
                    .map(|name| ("scope schema", name.clone())),
            );
            claimed.sort();
            // A Plane signing two artifacts with one ring claims the ring once; anything else it
            // names twice is a collision with itself.
            claimed.dedup_by(|left, right| left.0 == "signing ring" && left == right);
            for (at, (what, name)) in claimed.iter().enumerate() {
                let first = match claims.by_kind.get(&(*what, name.clone())) {
                    Some(first) => Some(first.clone()),
                    None => claimed[..at]
                        .contains(&(*what, name.clone()))
                        .then(|| plane.clone()),
                };
                if let Some(first) = first {
                    return Err(CompositionError::Collision {
                        what,
                        name: name.clone(),
                        first,
                        second: plane,
                    });
                }
            }
            for (what, name) in claimed {
                claims.by_kind.insert((what, name), plane.clone());
            }
            claims.planes.push(plane.clone());
        }

        Ok(Registration {
            plane,
            signers: declaration
                .signers
                .iter()
                .filter_map(|(artifact, ring)| {
                    self.rings
                        .get(ring)
                        .map(|keys| (*artifact, (*ring, Arc::clone(keys))))
                })
                .collect(),
            declared_signers: declaration
                .signers
                .iter()
                .map(|(artifact, _)| *artifact)
                .collect(),
            public: declaration
                .public_rings
                .iter()
                .filter_map(|ring| self.rings.get(ring).map(|keys| (*ring, Arc::clone(keys))))
                .collect(),
            declared_public: declaration.public_rings.clone(),
            audit: declaration.audit.iter().map(|(name, _)| *name).collect(),
            recorder: self.recorder.clone(),
            secrets,
        })
    }
}

/// A Plane's handles: what its declaration granted, and nothing else.
pub struct Registration {
    plane: String,
    signers: BTreeMap<&'static str, (RingId, Arc<dyn KeyManager>)>,
    declared_signers: Vec<&'static str>,
    public: BTreeMap<RingId, Arc<dyn KeyManager>>,
    declared_public: Vec<RingId>,
    audit: Vec<&'static str>,
    recorder: Option<AuditRecorder>,
    secrets: BTreeMap<&'static str, ResolvedSecret>,
}

/// A resolved secret's bytes, shared by the handles made from it, and its version.
type ResolvedSecret = (Arc<Zeroizing<Vec<u8>>>, String);

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("plane", &self.plane)
            .field("signers", &self.declared_signers)
            .field("public", &self.declared_public)
            .field("audit", &self.audit)
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Registration {
    /// The signer for artifact `T`: `None` when its ring is not composed in this deployment.
    pub fn signer<T: Artifact>(&self) -> Result<Option<Signer<T>>, CompositionError> {
        if !self.declared_signers.contains(&T::TYPE) {
            return Err(self.undeclared(format!("a signer for `{}`", T::TYPE)));
        }
        Ok(self.signers.get(T::TYPE).map(|(_, keys)| Signer {
            keys: Arc::clone(keys),
            artifact: PhantomData,
        }))
    }

    /// The public set of `ring`: `None` when the ring is not composed in this deployment.
    pub fn public_keys(&self, ring: RingId) -> Result<Option<PublicKeys>, CompositionError> {
        if !self.declared_public.contains(&ring) {
            return Err(self.undeclared(format!("the public keys of `{}`", ring.as_str())));
        }
        Ok(self.public.get(&ring).map(|keys| PublicKeys {
            ring,
            keys: Arc::clone(keys),
        }))
    }

    /// The audit handle for schema `T`: `None` when no audit recorder is composed.
    pub fn audit<T: AuditSchema>(&self) -> Result<Option<AuditHandle<T>>, CompositionError> {
        if !self.audit.contains(&T::NAME) {
            return Err(self.undeclared(format!("the audit schema `{}`", T::NAME)));
        }
        Ok(self.recorder.clone().map(|recorder| AuditHandle {
            recorder,
            schema: PhantomData,
        }))
    }

    /// The secret of purpose `T`, as a handle that never shows its bytes.
    pub fn secret<T: SecretPurpose>(&self) -> Result<SecretHandle<T>, CompositionError> {
        let (key, version) = self
            .secrets
            .get(T::NAME)
            .ok_or_else(|| self.undeclared(format!("the secret for `{}`", T::NAME)))?;
        Ok(SecretHandle {
            key: Arc::clone(key),
            version: version.clone(),
            purpose: PhantomData,
        })
    }

    fn undeclared(&self, what: String) -> CompositionError {
        CompositionError::Undeclared {
            plane: self.plane.clone(),
            what,
        }
    }
}

/// Signs artifact `T`, and nothing else, with the ring `T` names.
pub struct Signer<T: Artifact> {
    keys: Arc<dyn KeyManager>,
    artifact: PhantomData<fn() -> T>,
}

impl<T: Artifact> Clone for Signer<T> {
    fn clone(&self) -> Self {
        Self {
            keys: Arc::clone(&self.keys),
            artifact: PhantomData,
        }
    }
}

impl<T: Artifact> std::fmt::Debug for Signer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer<{}>({})", T::TYPE, T::RING.as_str())
    }
}

impl<T: Artifact> permguard_core::keys::Sign for Signer<T> {
    fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        self.keys.active_key_id()
    }

    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
        self.keys.sign(payload)
    }
}

impl<T: Artifact> permguard_core::keys::PublicSet for Signer<T> {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        self.keys.public_keys()
    }
}

/// A ring's public set: read, never signed with.
#[derive(Clone)]
pub struct PublicKeys {
    ring: RingId,
    keys: Arc<dyn KeyManager>,
}

impl std::fmt::Debug for PublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKeys({})", self.ring.as_str())
    }
}

impl permguard_core::keys::PublicSet for PublicKeys {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        self.keys.public_keys()
    }
}

/// Records the actions schema `T` declares, and refuses any other.
pub struct AuditHandle<T: AuditSchema> {
    recorder: AuditRecorder,
    schema: PhantomData<fn() -> T>,
}

impl<T: AuditSchema> Clone for AuditHandle<T> {
    fn clone(&self) -> Self {
        Self {
            recorder: self.recorder.clone(),
            schema: PhantomData,
        }
    }
}

impl<T: AuditSchema> std::fmt::Debug for AuditHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuditHandle<{}>", T::NAME)
    }
}

/// Why an audit handle did not record.
#[derive(Debug)]
pub enum AuditRefusal {
    /// The action is not one the handle's schema declares: nothing was recorded.
    Undeclared {
        schema: &'static str,
        action: String,
    },
    /// The sink refused or could not be reached.
    Sink(AuditError),
}

impl std::fmt::Display for AuditRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undeclared { schema, action } => write!(
                f,
                "the action `{action}` is not in the audit schema `{schema}`; nothing was recorded"
            ),
            Self::Sink(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuditRefusal {}

impl<T: AuditSchema> AuditHandle<T> {
    fn check(action: &str) -> Result<(), AuditRefusal> {
        if T::ACTIONS.contains(&action) {
            Ok(())
        } else {
            Err(AuditRefusal::Undeclared {
                schema: T::NAME,
                action: action.to_owned(),
            })
        }
    }

    /// The privacy policy the Host records subjects under, for a Plane that tokenises identifiers
    /// before they leave it: a capability that pseudonymises, never its key.
    pub fn pseudonymizer(&self) -> Option<Arc<dyn permguard_core::Pseudonymizer>> {
        self.recorder.pseudonymizer()
    }

    /// Records `action`, one of the schema's.
    pub async fn record(&self, action: &str, subject: Subject<'_>) -> Result<(), AuditRefusal> {
        Self::check(action)?;
        self.recorder
            .record(action, subject)
            .await
            .map_err(AuditRefusal::Sink)
    }

    /// Records `action`, one of the schema's, naming what it was done to.
    pub async fn record_on(
        &self,
        action: &str,
        subject: Subject<'_>,
        target: &str,
    ) -> Result<(), AuditRefusal> {
        Self::check(action)?;
        self.recorder
            .record_on(action, subject, target)
            .await
            .map_err(AuditRefusal::Sink)
    }
}

/// The secret of purpose `T`, usable only to compute an HMAC under it; its bytes are never shown.
pub struct SecretHandle<T: SecretPurpose> {
    key: Arc<Zeroizing<Vec<u8>>>,
    version: String,
    purpose: PhantomData<fn() -> T>,
}

impl<T: SecretPurpose> Clone for SecretHandle<T> {
    fn clone(&self) -> Self {
        Self {
            key: Arc::clone(&self.key),
            version: self.version.clone(),
            purpose: PhantomData,
        }
    }
}

impl<T: SecretPurpose> std::fmt::Debug for SecretHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretHandle<{}>({}, redacted)", T::NAME, self.version)
    }
}

impl<T: SecretPurpose> SecretHandle<T> {
    /// The version the secret was resolved at, which readers of an HMAC need beside it.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// HMAC-SHA256 under the secret, over `parts` in order; `None` only if the HMAC refused the
    /// key, which it does for no length — never a tag that merely looks valid.
    pub fn mac(&self, parts: &[&[u8]]) -> Option<[u8; 32]> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key).ok()?;
        for part in parts {
            mac.update(part);
        }
        Some(mac.finalize().into_bytes().into())
    }
}

/// Appends to a stream the Plane declared: built by the stream engine (WP-5.1).
#[derive(Debug)]
pub struct StreamProducer {
    _unbuildable: PhantomData<()>,
}

/// Calls a task on a peer Host the Plane declared: built by task routing (WP-4.x).
#[derive(Debug)]
pub struct TaskClient {
    _unbuildable: PhantomData<()>,
}

/// Authorizes a request against Host grants: built by the authorization model (WP-2.4).
#[derive(Debug)]
pub struct Authorization {
    _unbuildable: PhantomData<()>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::keys::Maintenance;
    use permguard_core::secrets::Secret;

    /// A ring that signs with a fixed tag, so a test can tell which ring signed.
    struct TaggedRing(&'static str);

    impl KeyManager for TaggedRing {
        fn name(&self) -> &'static str {
            "tagged"
        }
        fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
            Ok(Maintenance::default())
        }
    }

    impl permguard_core::keys::Sign for TaggedRing {
        fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
            Ok(KeyId::new(self.0))
        }

        fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
            let mut bytes = self.0.as_bytes().to_vec();
            bytes.extend_from_slice(payload);
            Ok(Signature::new(KeyId::new(self.0), "EdDSA", bytes))
        }
    }

    impl permguard_core::keys::PublicSet for TaggedRing {
        fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
            Ok(vec![Jwk::okp(self.0, "Ed25519", "EdDSA", "x")])
        }
    }
    struct Discard;

    impl permguard_core::AuditSink for Discard {
        fn name(&self) -> &'static str {
            "discard"
        }
        fn record<'a>(
            &'a self,
            _: &'a permguard_core::AuditEvent<'a>,
            _: Option<&'a dyn permguard_core::pseudonym::Pseudonymizer>,
        ) -> permguard_core::BoxFuture<'a, Result<(), AuditError>> {
            permguard_core::ready(Ok(()))
        }
    }

    struct FixedSecrets(Vec<u8>);

    impl SecretStore for FixedSecrets {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn resolve(&self, _: &SecretRef) -> permguard_core::secrets::Result<Secret> {
            Ok(Secret::new(self.0.clone()))
        }
    }

    struct Commitments;
    impl SecretPurpose for Commitments {
        const NAME: &'static str = "decision.commitment";
        const MIN_BYTES: usize = 32;
    }

    struct CatalogActions;
    impl AuditSchema for CatalogActions {
        const NAME: &'static str = "catalog.v1";
        const ACTIONS: &'static [&'static str] = &["zone.created", "zone.deleted"];
    }

    fn host() -> Host {
        Host::builder()
            .ring(CONTROL_ATTEST, Arc::new(TaggedRing("control")))
            .ring(DATA_ATTEST, Arc::new(TaggedRing("data")))
            .ring(HOST_OPERATIONS, Arc::new(TaggedRing("operations")))
            .build()
    }

    #[test]
    fn a_plane_signs_what_it_declared_with_the_ring_the_artifact_names() {
        let host = host();
        let data = host
            .register(
                Declaration::new("data")
                    .signs::<DecisionBatchV1>()
                    .signs::<EventBatchV1>(),
                None,
            )
            .expect("registers");
        let signer = data
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("the ring is composed");
        assert!(
            signer
                .sign(b"x")
                .expect("signs")
                .bytes()
                .starts_with(b"data")
        );
        let refused = data.signer::<HeadStatementV1>().expect_err("not declared");
        assert!(
            matches!(refused, CompositionError::Undeclared { .. }),
            "{refused}"
        );
        let refused = data.public_keys(CONTROL_ATTEST).expect_err("not declared");
        assert!(
            matches!(refused, CompositionError::Undeclared { .. }),
            "{refused}"
        );
    }

    #[test]
    fn colliding_declarations_fail_registration() {
        let host = host();
        host.register(Declaration::new("data").signs::<DecisionBatchV1>(), None)
            .expect("first");
        for (second, what) in [
            (
                Declaration::new("other").signs::<DecisionBatchV1>(),
                "artifact type",
            ),
            (
                Declaration::new("other").signs::<EventBatchV1>(),
                "signing ring",
            ),
        ] {
            let refused = host.register(second, None).expect_err("collides");
            assert!(
                matches!(&refused, CompositionError::Collision { what: found, .. } if *found == what),
                "{refused}"
            );
        }
        let host = self::host();
        host.register(
            Declaration::new("control")
                .produces_stream("permguard.decisions")
                .handles_task("notp.mirror")
                .owns_scope_schema("zone")
                .audits::<CatalogActions>(),
            None,
        )
        .expect("first");
        for (second, what) in [
            (
                Declaration::new("data").produces_stream("permguard.decisions"),
                "stream descriptor",
            ),
            (
                Declaration::new("data").handles_task("notp.mirror"),
                "task type",
            ),
            (
                Declaration::new("data").owns_scope_schema("zone"),
                "scope schema",
            ),
            (
                Declaration::new("data").audits::<CatalogActions>(),
                "audit schema",
            ),
        ] {
            let refused = host.register(second, None).expect_err("collides");
            assert!(
                matches!(&refused, CompositionError::Collision { what: found, .. } if *found == what),
                "{refused}"
            );
        }
        let refused = host
            .register(Declaration::new("control"), None)
            .expect_err("twice");
        assert!(matches!(refused, CompositionError::AlreadyRegistered(_)));
        let refused = self::host()
            .register(
                Declaration::new("data")
                    .produces_stream("s")
                    .produces_stream("s"),
                None,
            )
            .expect_err("a Plane colliding with itself");
        assert!(
            matches!(refused, CompositionError::Collision { .. }),
            "{refused}"
        );
    }

    #[tokio::test]
    async fn an_audit_handle_records_only_its_schemas_actions() {
        let recorder = AuditRecorder::new(Arc::new(Discard));
        let host = Host::builder().audit(recorder).build();
        let control = host
            .register(Declaration::new("control").audits::<CatalogActions>(), None)
            .expect("registers");
        let audit = control
            .audit::<CatalogActions>()
            .expect("declared")
            .expect("composed");
        audit
            .record("zone.created", Subject::System("catalog"))
            .await
            .expect("declared action");
        let refused = audit
            .record("key.exported", Subject::System("catalog"))
            .await
            .expect_err("not in the schema");
        assert!(
            matches!(refused, AuditRefusal::Undeclared { .. }),
            "{refused}"
        );
    }

    #[test]
    fn a_secret_handle_macs_without_showing_its_bytes() {
        let host = host();
        let data = host
            .register(
                Declaration::new("data")
                    .uses_secret::<Commitments>(SecretRef::new("commitment"), "v3"),
                Some(&FixedSecrets(vec![7u8; 32])),
            )
            .expect("registers");
        let secret = data.secret::<Commitments>().expect("declared");
        assert_eq!(secret.version(), "v3");
        let expected = {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[7u8; 32]).expect("key");
            mac.update(b"domain\n");
            mac.update(b"value");
            <[u8; 32]>::from(mac.finalize().into_bytes())
        };
        assert_eq!(secret.mac(&[b"domain\n", b"value"]), Some(expected));
        assert!(
            !format!("{secret:?}").contains("07"),
            "Debug never shows the key"
        );

        let short = Host::builder()
            .build()
            .register(
                Declaration::new("data")
                    .uses_secret::<Commitments>(SecretRef::new("commitment"), "v1"),
                Some(&FixedSecrets(vec![1u8; 8])),
            )
            .expect_err("too short for the purpose");
        assert!(matches!(short, CompositionError::Secret { .. }), "{short}");

        // A refused registration holds nothing: the same plane registers once its secret is fixed,
        // and what it declared is not attributed to it meanwhile.
        let host = Host::builder().build();
        let declaration = || {
            Declaration::new("data")
                .signs::<DecisionBatchV1>()
                .uses_secret::<Commitments>(SecretRef::new("commitment"), "v1")
        };
        host.register(declaration(), Some(&FixedSecrets(vec![1u8; 8])))
            .expect_err("too short");
        host.register(declaration(), Some(&FixedSecrets(vec![1u8; 32])))
            .expect("the failed attempt left no claim behind");
    }
}
