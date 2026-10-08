// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's composition core: one implementation of every generic capability, and the typed,
//! least-privilege handles a Plane receives for what it declared (P1).
//!
//! ```text
//! composition (permguard-server)
//!   ─▶ Host::builder()          the rings, the audit recorder, the zone keys: built once
//!   ─▶ host.register(declaration)   per Plane, before its state opens; collisions refused
//!   ─▶ Registration              the Plane's handles, limited to what it declared
//! ```
//!
//! | Handle             | What a Plane can do with it                     | What it cannot reach                     |
//! | ------------------ | ----------------------------------------------- | ---------------------------------------- |
//! | [`Signer<T>`]      | sign with the ring artifact `T` names           | the key manager, another ring, any key   |
//! | [`PublicKeys`]     | read a declared ring's public set               | signing                                  |
//! | [`AuditHandle<T>`] | record the actions schema `T` declares          | another action, the sink, the trail      |
//! | `ZoneHandle`       | a MAC under the zone key of a declared purpose  | any key's bytes, another purpose's keys  |
//! | [`StreamProducer`], [`TaskClient`], [`Authorization`] | declared now; built by their packages | — |
//!
//! Least privilege is a property of the types: no handle has an accessor that returns the key
//! manager, a key's bytes or a Host-private path, so a Plane holding one cannot widen it. A
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

#[cfg(test)]
use permguard_core::keys::Signature;
use permguard_core::keys::{Jwk, KeyId, KeyManager, SigningRing};
use permguard_core::server::AuditRecorder;
use permguard_core::{AuditError, AuditEvent, Subject};

use crate::time::TimeGuard;

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
    /// Whether the artifact carries a time a verifier relies on: such an artifact is not signed
    /// while the Host's clock is in anomaly (WP-2.12). Evidence ordered by sequence is not.
    const TIME_SENSITIVE: bool;
}

/// Today's signed NOTP head statement, signed by the Control Plane.
pub struct HeadStatementV1;

impl Artifact for HeadStatementV1 {
    const TYPE: &'static str = permguard_core::domains::protected::NOTP_HEAD;
    const RING: RingId = CONTROL_ATTEST;
    /// `signed_at` is what a verifier judges a head's freshness by.
    const TIME_SENSITIVE: bool = true;
}

/// A decision batch, signed by the Data Plane that decided.
pub struct DecisionBatchV1;

impl Artifact for DecisionBatchV1 {
    const TYPE: &'static str = permguard_core::domains::protected::DECISION_BATCH;
    const RING: RingId = DATA_ATTEST;
    /// Evidence: ordered by sequence, it keeps shipping through an anomaly.
    const TIME_SENSITIVE: bool = false;
}

/// An event batch, signed by the Data Plane that recorded the history.
pub struct EventBatchV1;

impl Artifact for EventBatchV1 {
    const TYPE: &'static str = permguard_core::domains::protected::EVENT_BATCH;
    const RING: RingId = DATA_ATTEST;
    /// Evidence: ordered by sequence, it keeps shipping through an anomaly.
    const TIME_SENSITIVE: bool = false;
}

/// The actions an audit schema lets its holder record.
pub trait AuditSchema: 'static {
    /// The schema's name, unique across Planes.
    const NAME: &'static str;
    /// Every action the holder may record.
    const ACTIONS: &'static [&'static str];
}

/// What a Plane declares before its state opens.
#[derive(Debug, Clone, Default)]
pub struct Declaration {
    plane: String,
    signers: Vec<(&'static str, RingId)>,
    public_rings: Vec<RingId>,
    audit: Vec<(&'static str, &'static [&'static str])>,
    zone_keys: Vec<crate::secrets::ZonePurpose>,
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

    /// Declares the zone keys of `purpose` this Plane MACs under (WP-3.3): a handle that never
    /// shows a key, and answers no MAC for a zone or scope this Host holds no key for.
    pub fn uses_zone_key(mut self, purpose: crate::secrets::ZonePurpose) -> Self {
        if !self.zone_keys.contains(&purpose) {
            self.zone_keys.push(purpose);
        }
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
    /// A Plane declared, as its own artifact, a content type only the Host identity signs: the
    /// identity document, a succession, a session or its proof, a ring binding (WP-2.3).
    Reserved { plane: String, artifact: String },
}

/// The content types the Host identity signs and no Plane may declare as its artifact: a verifier
/// of a session proof or a ring binding never meets one a Plane's ring signed (WP-2.3).
pub const HOST_RESERVED: &[&str] = &[
    permguard_core::domains::protected::HOST_IDENTITY,
    permguard_core::domains::protected::HOST_PROOF,
    permguard_core::domains::protected::HOST_SESSION,
    permguard_core::domains::protected::HOST_SUCCESSION,
    permguard_core::domains::protected::HOST_RING_BINDING,
];

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
            Self::Reserved { plane, artifact } => write!(
                f,
                "the plane `{plane}` declared `{artifact}` as its artifact, which only the Host \
                 identity signs"
            ),
        }
    }
}

impl std::error::Error for CompositionError {}

/// The Host: every generic capability, implemented once.
pub struct Host {
    rings: BTreeMap<RingId, Arc<dyn KeyManager>>,
    recorder: Option<AuditRecorder>,
    authorization: Option<Arc<Authorization>>,
    time: Arc<TimeGuard>,
    zone_keys: BTreeMap<crate::secrets::ZonePurpose, Arc<crate::secrets::ZoneHandle>>,
    host_id: Option<[u8; 16]>,
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
    authorization: Option<Arc<Authorization>>,
    time: Option<Arc<TimeGuard>>,
    zone_keys: BTreeMap<crate::secrets::ZonePurpose, Arc<crate::secrets::ZoneHandle>>,
    host_id: Option<[u8; 16]>,
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
    /// The authorization every registered Plane decides with. A Host built without one hands
    /// out [`Authorization::closed`]: nothing is allowed, which is the fail-closed default.
    pub fn authorization(mut self, authorization: Arc<Authorization>) -> Self {
        self.authorization = Some(authorization);
        self
    }

    /// The time guard every signer of a time-sensitive artifact consults. A Host built without
    /// one guards with the operating system's clocks and the default bound, kept on no volume.
    pub fn time(mut self, time: Arc<TimeGuard>) -> Self {
        self.time = Some(time);
        self
    }

    /// The zone keys of one purpose this Host holds, as coordinator or as a member (WP-3.3).
    pub fn zone_key(mut self, handle: crate::secrets::ZoneHandle) -> Self {
        self.zone_keys.insert(handle.purpose(), Arc::new(handle));
        self
    }

    /// This Host's `host_id`, the salt of every Host-local key a Plane derives from a root of
    /// its own (WP-3.3).
    pub fn host_id(mut self, host_id: [u8; 16]) -> Self {
        self.host_id = Some(host_id);
        self
    }

    pub fn build(self) -> Host {
        Host {
            rings: self.rings,
            recorder: self.recorder,
            authorization: self.authorization,
            time: self.time.unwrap_or_else(|| {
                Arc::new(TimeGuard::system(
                    permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
                ))
            }),
            zone_keys: self.zone_keys,
            host_id: self.host_id,
            claimed: std::sync::Mutex::new(Claims::default()),
        }
    }
}

impl Host {
    /// A builder; only a composition root calls it.
    pub fn builder() -> HostBuilder {
        HostBuilder::default()
    }

    /// Registers a Plane's declaration and answers its handles. A Plane holds no secret: what it
    /// MACs under is a zone key handle the Host holds (WP-3.3).
    ///
    /// Refuses a Plane registered before, and any declaration that collides with one already
    /// registered: an artifact type, a ring signed by two Planes, an audit schema, a stream
    /// descriptor, a task type or a scope schema.
    pub fn register(&self, declaration: Declaration) -> Result<Registration, CompositionError> {
        let plane = declaration.plane.clone();
        if let Some((artifact, _)) = declaration
            .signers
            .iter()
            .find(|(artifact, _)| HOST_RESERVED.contains(artifact))
        {
            return Err(CompositionError::Reserved {
                plane,
                artifact: (*artifact).to_owned(),
            });
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
            zone_keys: declaration
                .zone_keys
                .iter()
                .filter_map(|purpose| {
                    self.zone_keys
                        .get(purpose)
                        .map(|handle| (*purpose, Arc::clone(handle)))
                })
                .collect(),
            declared_zone_keys: declaration.zone_keys.clone(),
            host_id: self.host_id,
            authorization: self
                .authorization
                .clone()
                .unwrap_or_else(|| Arc::new(Authorization::closed())),
            time: Arc::clone(&self.time),
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
    zone_keys: BTreeMap<crate::secrets::ZonePurpose, Arc<crate::secrets::ZoneHandle>>,
    declared_zone_keys: Vec<crate::secrets::ZonePurpose>,
    host_id: Option<[u8; 16]>,
    authorization: Arc<Authorization>,
    time: Arc<TimeGuard>,
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("plane", &self.plane)
            .field("signers", &self.declared_signers)
            .field("public", &self.declared_public)
            .field("audit", &self.audit)
            .field("zone_keys", &self.declared_zone_keys)
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
            time: Arc::clone(&self.time),
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

    /// The Host's authorization, which every Plane decides with: deny by default, and closed
    /// when the Host built none.
    pub fn authorization(&self) -> Arc<Authorization> {
        Arc::clone(&self.authorization)
    }

    /// The zone keys of `purpose`: `None` when this Host holds none (no coordinator root and
    /// nothing delivered), never another purpose's.
    pub fn zone_key(
        &self,
        purpose: crate::secrets::ZonePurpose,
    ) -> Result<Option<Arc<crate::secrets::ZoneHandle>>, CompositionError> {
        if !self.declared_zone_keys.contains(&purpose) {
            return Err(self.undeclared(format!("the zone keys of `{}`", purpose.as_str())));
        }
        Ok(self.zone_keys.get(&purpose).cloned())
    }

    /// This Host's `host_id`, when the composition knows it: public, the salt of a Host-local
    /// key a Plane derives from its own root.
    pub fn host_id(&self) -> Option<[u8; 16]> {
        self.host_id
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
    time: Arc<TimeGuard>,
    artifact: PhantomData<fn() -> T>,
}

impl<T: Artifact> Clone for Signer<T> {
    fn clone(&self) -> Self {
        Self {
            keys: Arc::clone(&self.keys),
            time: Arc::clone(&self.time),
            artifact: PhantomData,
        }
    }
}

impl<T: Artifact> std::fmt::Debug for Signer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer<{}>({})", T::TYPE, T::RING.as_str())
    }
}

mod sealed {
    /// Only the Host implements [`super::Payload`]: what reaches a ring is framed here.
    pub trait Sealed {}
}

/// What a typed signer signs: an artifact's payload, in the canonical form its format fixes
/// (WP-3.2, owner decision of 2026-10-08). A Plane holds a [`Signer<T>`] and hands it a payload;
/// it never reaches a `sign(bytes)`. Sealed: the Host writes every signing input — the head
/// statement's COSE structure, a batch's protected header — so no implementation outside it can
/// hand a ring bytes of its own choosing.
///
/// ```compile_fail
/// use permguard_host::composition::{DecisionBatchV1, Payload};
///
/// struct Forged;
///
/// impl Payload for Forged {
///     type Artifact = DecisionBatchV1;
///     type Signed = ();
///
///     fn sign_with(
///         &self,
///         _: &dyn permguard_core::keys::SigningRing,
///     ) -> permguard_core::keys::Result<()> {
///         Ok(())
///     }
/// }
/// ```
pub trait Payload: sealed::Sealed {
    /// The artifact the payload is the content of: a `Signer<Self::Artifact>` signs it.
    type Artifact: Artifact;
    /// The signed artifact, as its format writes it.
    type Signed;
    /// Signs `self` with `keys`, the ring of [`Self::Artifact`], as the artifact's format does:
    /// the protected header naming the ring's active key, the canonical signing input.
    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Self::Signed>;
}

impl<T: Artifact> Signer<T> {
    /// Signs `payload`, a payload of `T` and of nothing else; refused while the Host's clock is in
    /// anomaly for an artifact that carries a time (WP-2.12).
    pub fn sign<P: Payload<Artifact = T>>(
        &self,
        payload: &P,
    ) -> permguard_core::keys::Result<P::Signed> {
        if T::TIME_SENSITIVE
            && let Err(anomaly) = self.time.trusted_now()
        {
            return Err(permguard_core::KeyError::ClockAnomaly {
                detail: anomaly.to_string(),
            });
        }
        payload.sign_with(self.keys.as_ref())
    }

    /// The key that signs now.
    pub fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        self.keys.active_key_id()
    }

    /// The time an artifact signed now carries: the Host's time guard (WP-2.12).
    pub fn signing_time(&self) -> i64 {
        self.time.now()
    }
}

/// A NOTP head statement is the payload of [`HeadStatementV1`]: a COSE_Sign1 under the ring's
/// active key, its `kid` the key's, refused when the ring rotated mid-signature.
impl sealed::Sealed for permguard_objects::statement::HeadStatement {}

impl Payload for permguard_objects::statement::HeadStatement {
    type Artifact = HeadStatementV1;
    type Signed = Vec<u8>;

    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Vec<u8>> {
        let kid = keys.active_key_id()?;
        let failed = std::cell::RefCell::new(None::<permguard_core::KeyError>);
        let signed = permguard_objects::statement::SignedHead::sign_with(
            self,
            kid.as_str().as_bytes(),
            |bytes| {
                let signature = keys.sign(bytes).map_err(|error| {
                    let detail = error.to_string();
                    *failed.borrow_mut() = Some(error);
                    permguard_objects::statement::StatementError::Signer(detail)
                })?;
                if signature.key_id() != &kid {
                    return Err(permguard_objects::statement::StatementError::Signer(
                        "the signing key rotated mid-signature".to_owned(),
                    ));
                }
                Ok(signature.bytes().to_vec())
            },
        )
        .map_err(|error| {
            failed.take().unwrap_or_else(|| {
                permguard_core::KeyError::backend(format!("signing the head statement: {error}"))
            })
        })?;
        signed.encode().map_err(|error| {
            permguard_core::KeyError::backend(format!("encoding the head statement: {error}"))
        })
    }
}

/// An artifact signed as a JWS whose protected header the Host writes (WP-3.2). Sealed: the
/// framings are the Host's, so no Plane makes a JWS of its own on its ring.
pub trait JwsArtifact: Artifact + sealed::Sealed {
    /// The algorithm the header declares, and the only one the signature may be made with.
    const ALGORITHM: &'static str;
    /// Whether the header declares [`Artifact::TYPE`] as its `typ`.
    const DECLARES_TYPE: bool;
}

impl sealed::Sealed for DecisionBatchV1 {}
impl sealed::Sealed for EventBatchV1 {}

/// A decision batch's header is `{"alg","kid"}`.
impl JwsArtifact for DecisionBatchV1 {
    const ALGORITHM: &'static str = "EdDSA";
    const DECLARES_TYPE: bool = false;
}

/// An event batch's header is `{"alg","typ","kid"}`.
impl JwsArtifact for EventBatchV1 {
    const ALGORITHM: &'static str = "EdDSA";
    const DECLARES_TYPE: bool = true;
}

/// A JWS payload of `T`: the canonical bytes its format fixes. The Host writes the protected
/// header and the signing input `protected || "." || payload`.
pub struct Jws<'a, T> {
    payload: &'a [u8],
    artifact: PhantomData<T>,
}

impl<'a, T: JwsArtifact> Jws<'a, T> {
    /// The payload `bytes`, to be signed as `T`.
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            payload,
            artifact: PhantomData,
        }
    }
}

/// A signed JWS's three parts, base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsParts {
    /// The protected header the Host wrote.
    pub protected: String,
    /// The payload.
    pub payload: String,
    /// The signature over `protected || "." || payload`.
    pub signature: String,
}

/// Why a JWS was not signed.
#[derive(Debug)]
pub enum JwsError {
    /// The ring did not sign.
    Key(permguard_core::KeyError),
    /// The ring signed with an algorithm the artifact's header does not declare.
    Algorithm(String),
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(error) => write!(f, "{error}"),
            Self::Algorithm(found) => write!(f, "the ring signed with `{found}`"),
        }
    }
}

impl std::error::Error for JwsError {}

#[derive(serde::Serialize)]
struct JwsHeader<'a> {
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
    kid: &'a str,
}

/// Signs `payload` as a JWS of `T` under `keys`' active key: the one framing of a batch, used by
/// the Host's [`Signer<T>`] and by a tool that holds a ring itself.
pub fn sign_jws<T: JwsArtifact>(
    payload: &[u8],
    keys: &dyn permguard_core::keys::Sign,
) -> Result<JwsParts, JwsError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    let kid = keys.active_key_id().map_err(JwsError::Key)?;
    let header = serde_json::to_vec(&JwsHeader {
        alg: T::ALGORITHM,
        typ: T::DECLARES_TYPE.then_some(T::TYPE),
        kid: kid.as_str(),
    })
    .map_err(|error| {
        JwsError::Key(permguard_core::KeyError::backend(format!(
            "writing the protected header: {error}"
        )))
    })?;
    let protected = B64.encode(header);
    let payload = B64.encode(payload);
    let signature = keys
        .sign(format!("{protected}.{payload}").as_bytes())
        .map_err(JwsError::Key)?;
    if signature.algorithm() != T::ALGORITHM {
        return Err(JwsError::Algorithm(signature.algorithm().to_owned()));
    }
    if signature.key_id() != &kid {
        return Err(JwsError::Key(permguard_core::KeyError::backend(
            "the signing key rotated mid-signature",
        )));
    }
    Ok(JwsParts {
        protected,
        payload,
        signature: B64.encode(signature.bytes()),
    })
}

impl<T: JwsArtifact> sealed::Sealed for Jws<'_, T> {}

impl<T: JwsArtifact> Payload for Jws<'_, T> {
    type Artifact = T;
    type Signed = JwsParts;

    fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<JwsParts> {
        sign_jws::<T>(self.payload, keys).map_err(|error| match error {
            JwsError::Key(error) => error,
            JwsError::Algorithm(_) => permguard_core::KeyError::backend(error.to_string()),
        })
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

    /// Records `event`, whose action is one of the schema's, as built: a resource narrowed below
    /// the root the Host assigns the Plane, an outcome, facts or an operation's phase.
    pub async fn record_event(&self, event: &AuditEvent<'_>) -> Result<(), AuditRefusal> {
        Self::check(event.action())?;
        self.recorder
            .record_event(event)
            .await
            .map_err(AuditRefusal::Sink)
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

/// Authorizes a request against Host grants: the handle of [`crate::authz::Authorization`], one
/// per Host, handed to every registered Plane (WP-2.4).
pub use crate::authz::Authorization;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::keys::Maintenance;

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
    /// A payload of `T` whose signed form is the raw signature over its bytes, for the tests.
    struct Probe<T>(&'static [u8], PhantomData<T>);

    impl<T> Probe<T> {
        fn new(bytes: &'static [u8]) -> Self {
            Self(bytes, PhantomData)
        }
    }

    impl<T> sealed::Sealed for Probe<T> {}

    impl<T: Artifact> Payload for Probe<T> {
        type Artifact = T;
        type Signed = Signature;

        fn sign_with(&self, keys: &dyn SigningRing) -> permguard_core::keys::Result<Signature> {
            keys.sign(self.0)
        }
    }

    /// WP-3.2: a Plane's signer signs payloads only. Resolved by autoref: the method of the
    /// `Sign` probe wins only where the type implements `Sign`.
    #[test]
    fn a_plane_signer_has_no_signature_over_bytes() {
        struct Probe<T>(PhantomData<T>);
        trait ViaSign {
            fn signs_bytes(&self) -> bool {
                true
            }
        }
        impl<T: permguard_core::keys::Sign> ViaSign for Probe<T> {}
        trait Otherwise {
            fn signs_bytes(&self) -> bool {
                false
            }
        }
        impl<T> Otherwise for &Probe<T> {}

        assert!(!(&Probe::<Signer<HeadStatementV1>>(PhantomData)).signs_bytes());
        assert!(!(&Probe::<Signer<DecisionBatchV1>>(PhantomData)).signs_bytes());
        assert!(!(&Probe::<Signer<EventBatchV1>>(PhantomData)).signs_bytes());
        // The probe tells: a ring does sign bytes.
        assert!(Probe::<TaggedRing>(PhantomData).signs_bytes());
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

    /// WP-3.2: the Host writes a batch's protected header and signing input; the Plane supplies
    /// the payload only, and a ring signing with another algorithm is refused.
    #[test]
    fn the_host_frames_a_batch_and_the_plane_supplies_its_payload() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let registration = host()
            .register(
                Declaration::new("data")
                    .signs::<DecisionBatchV1>()
                    .signs::<EventBatchV1>(),
            )
            .expect("registers");
        let events = registration
            .signer::<EventBatchV1>()
            .expect("declared")
            .expect("composed");
        let decisions = registration
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("composed");

        let event = events
            .sign(&Jws::<EventBatchV1>::new(b"{}"))
            .expect("signs");
        assert_eq!(
            B64.decode(&event.protected).expect("base64url"),
            br#"{"alg":"EdDSA","typ":"permguard.event.batch.v1","kid":"data"}"#
        );
        assert_eq!(event.payload, B64.encode(b"{}"));
        assert_eq!(
            B64.decode(&event.signature).expect("base64url"),
            format!("data{}.{}", event.protected, event.payload).into_bytes()
        );
        let decision = decisions
            .sign(&Jws::<DecisionBatchV1>::new(b"{}"))
            .expect("signs");
        assert_eq!(
            B64.decode(&decision.protected).expect("base64url"),
            br#"{"alg":"EdDSA","kid":"data"}"#
        );

        struct Es256;
        impl permguard_core::keys::Sign for Es256 {
            fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
                Ok(KeyId::new("p256"))
            }
            fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
                Ok(Signature::new(
                    KeyId::new("p256"),
                    "ES256",
                    payload.to_vec(),
                ))
            }
        }
        assert!(matches!(
            sign_jws::<DecisionBatchV1>(b"{}", &Es256),
            Err(JwsError::Algorithm(found)) if found == "ES256"
        ));
    }

    #[test]
    fn a_plane_signs_what_it_declared_with_the_ring_the_artifact_names() {
        let host = host();
        let data = host
            .register(
                Declaration::new("data")
                    .signs::<DecisionBatchV1>()
                    .signs::<EventBatchV1>(),
            )
            .expect("registers");
        let signer = data
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("the ring is composed");
        assert!(
            signer
                .sign(&Probe::<DecisionBatchV1>::new(b"x"))
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

    /// WP-2.12: a backward jump beyond the bound stops the time-sensitive signatures — a head
    /// statement's `signed_at` — and leaves evidence signing, which orders by sequence.
    #[test]
    fn a_clock_anomaly_stops_time_sensitive_signatures_and_leaves_evidence_signing() {
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

        let wall = Arc::new(ManualClock::at(1_800_000_000));
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            Arc::new(ManualMonotonic::default()),
            std::time::Duration::from_secs(30),
        ));
        let host = Host::builder()
            .ring(CONTROL_ATTEST, Arc::new(TaggedRing("control")))
            .ring(DATA_ATTEST, Arc::new(TaggedRing("data")))
            .time(time)
            .build();
        let control = host
            .register(Declaration::new("control").signs::<HeadStatementV1>())
            .expect("registers");
        let data = host
            .register(Declaration::new("data").signs::<DecisionBatchV1>())
            .expect("registers");
        let heads = control
            .signer::<HeadStatementV1>()
            .expect("declared")
            .expect("composed");
        let batches = data
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("composed");
        let head = Probe::<HeadStatementV1>::new(b"head");
        let batch = Probe::<DecisionBatchV1>::new(b"batch");
        heads.sign(&head).expect("a sound clock signs");

        wall.jump(-31);
        let refused = heads.sign(&head).expect_err("in anomaly");
        assert!(
            matches!(refused, permguard_core::KeyError::ClockAnomaly { .. }),
            "{refused}"
        );
        assert!(refused.is_retryable());
        batches.sign(&batch).expect("evidence keeps signing");

        wall.jump(31);
        heads.sign(&head).expect("the wall clock caught up");
    }

    #[test]
    fn colliding_declarations_fail_registration() {
        let host = host();
        host.register(Declaration::new("data").signs::<DecisionBatchV1>())
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
            let refused = host.register(second).expect_err("collides");
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
            let refused = host.register(second).expect_err("collides");
            assert!(
                matches!(&refused, CompositionError::Collision { what: found, .. } if *found == what),
                "{refused}"
            );
        }
        let refused = host
            .register(Declaration::new("control"))
            .expect_err("twice");
        assert!(matches!(refused, CompositionError::AlreadyRegistered(_)));
        let refused = self::host()
            .register(
                Declaration::new("data")
                    .produces_stream("s")
                    .produces_stream("s"),
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
            .register(Declaration::new("control").audits::<CatalogActions>())
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

    /// A Plane narrows its records below the root the Host assigns it, through its handle, and the
    /// engine writes them in the narrowed resource's own trail (WP-3.5).
    #[tokio::test]
    async fn a_plane_narrows_its_resource_through_its_handle() {
        use crate::audit::{Class, Engine, HostAuditSink, Stamp, trail};
        use crate::time::{ManualClock, ManualMonotonic, TimeGuard};
        use permguard_core::assurance::AssuranceProfile;

        let root = std::env::temp_dir().join(format!(
            "permguard-host-composition-narrow-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = crate::storage::volume::Volume::claim(&root, AssuranceProfile::Development)
            .expect("claimed");
        let time = Arc::new(TimeGuard::new(
            Arc::new(ManualClock::at(1_800_000_000)),
            Arc::new(ManualMonotonic::default()),
            std::time::Duration::from_secs(30),
        ));
        let stamp = Stamp {
            host_id: [1; 16],
            boot_id: [2; 16],
            build: "9.9.9".to_owned(),
            config_revision: permguard_objects::digest::Digest::compute(b"settings"),
        };
        let engine = Arc::new(Engine::open(&volume, stamp, time, None).expect("opens"));
        let sink = Arc::new(HostAuditSink::new(Arc::clone(&engine), None));
        let host = Host::builder().audit(AuditRecorder::new(sink)).build();
        let audit = host
            .register(Declaration::new("control").audits::<CatalogActions>())
            .expect("registers")
            .audit::<CatalogActions>()
            .expect("declared")
            .expect("composed");
        audit
            .record_event(
                &AuditEvent::new("zone.created", Subject::System("catalog"))
                    .in_resource("plane/control/zone/z1"),
            )
            .await
            .expect("narrowed below the Plane's root");
        let narrowed = engine
            .trail_dir(Class::Security, "plane/control/zone/z1")
            .expect("its own trail");
        assert_eq!(trail::verify(&narrowed).expect("verifies"), 1);
        let refused = audit
            .record_event(
                &AuditEvent::new("zone.created", Subject::System("catalog")).in_resource("host"),
            )
            .await
            .expect_err("not below the Plane's root");
        assert!(refused.to_string().contains("not below it"), "{refused}");
        let refused = audit
            .record_event(&AuditEvent::new("key.exported", Subject::System("catalog")))
            .await
            .expect_err("not in the schema");
        assert!(
            matches!(refused, AuditRefusal::Undeclared { .. }),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
