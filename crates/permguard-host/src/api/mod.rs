// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API facade (WP-2.5): every operation of `/host/v1` and `permguard.host.v1` defined
//! once, behind the common envelope of the Host API contract. The transports own decoding, the
//! authenticated context and response mapping, and nothing else.
//!
//! The envelope, as the contract names it:
//!
//! | Element    | Here                                                                            |
//! | ---------- | ------------------------------------------------------------------------------- |
//! | request id | every mutation carries one; [`replay`] returns the stored result inside the window |
//! | revision   | a mutation states the revision it expects; a lost race is `revision_mismatch`     |
//! | receipt    | every mutation answers a [`Receipt`]: operation id, revision, audit reference      |
//! | errors     | `{class, code, message}`; a conflict carries the current revision                  |
//! | bounds     | the transport bounds the body; [`bounds`] bounds each principal's rate and concurrency |
//!
//! Every route authorizes before it acts: a caller without a grant reads nothing and changes
//! nothing, and learns of a route a later package serves only after it is admitted. What a
//! transport decides before the facade is its own shape check — a body that is not the request's
//! shape is refused as such on REST, as a message that does not decode is on gRPC — and nothing
//! of the state.

pub mod bounds;
pub mod config;
pub mod grants;
pub mod identity;
pub mod keys;
pub mod replay;
pub mod sessions;
pub mod status;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, Principal, Resource};
use permguard_core::{AccessDenial, ApiError, ErrorClass, Health, codes};

use crate::authz::{Authorization, GrantStore};
use crate::operations::journal::{Initiator, OperationId, RequestKey};
use crate::operations::mutation::{
    self, Applying, Begin, Failure, MutationError, Mutations, Outcome,
};

pub use bounds::Bounds;
pub use config::{Effective, Setting};
pub use grants::{CreateGrant, GrantView, Grants, PlanRevoke, Planned, Revoked, RunRevoke};
pub use identity::{IdentityRotated, IdentityView, RotateIdentity};
pub use keys::{
    KeyRevoked, PlanKeyRevoke, RingBinding, RingBindings, RingRotated, RingSummary, RingView,
    Rings, RotateRing, RunKeyRevoke,
};
pub use replay::Replay;
pub use status::{Assurance, ComponentView, DegradedView, StatusView};

/// The `component` every record of the facade carries.
pub const COMPONENT: &str = "host-api";

/// The longest request id a mutation may carry, in bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// What the facade refuses with: a domain refusal, a conflict naming the current revision, or a
/// denial of access. The transports render each the one way every Permguard surface does.
#[derive(Debug)]
pub enum Refusal {
    /// A domain refusal: the taxonomy's class and a stable code.
    Api(ApiError),
    /// A lost race: the revision the mutation expected is not the current one, which travels
    /// beside the refusal so the caller can read, decide and retry.
    Conflict { error: ApiError, revision: u64 },
    /// No usable credential, or a principal without the grant.
    Denied(AccessDenial),
}

impl From<AccessDenial> for Refusal {
    fn from(denial: AccessDenial) -> Self {
        Self::Denied(denial)
    }
}

impl From<ApiError> for Refusal {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl Refusal {
    /// A refusal of class `class` with the stable `code`.
    pub fn new(class: ErrorClass, code: &'static str, message: impl Into<String>) -> Self {
        Self::Api(ApiError::new(class, code, message))
    }

    /// The route exists in the contract and a later package serves it.
    pub fn not_served_yet(what: &str, package: &str) -> Self {
        Self::new(
            ErrorClass::Unavailable,
            codes::host::NOT_SERVED_YET,
            format!("{what} is not served by this build; it arrives with {package}"),
        )
    }

    /// A mutation that expected `expected` while the current revision is `current`.
    pub fn revision_mismatch(expected: u64, current: u64) -> Self {
        Self::Conflict {
            error: ApiError::new(
                ErrorClass::Conflict,
                codes::host::REVISION_MISMATCH,
                format!("the mutation expected revision {expected}, the current one is {current}"),
            ),
            revision: current,
        }
    }

    /// The error of this refusal, for the transports; a denial has none.
    pub fn error(&self) -> Option<&ApiError> {
        match self {
            Self::Api(error) | Self::Conflict { error, .. } => Some(error),
            Self::Denied(_) => None,
        }
    }
}

/// What a mutation carries beside its own members: its request id and, when the record it
/// replaces has one, the revision it expects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutation {
    /// The caller's name for this attempt; a retry carries the same one.
    pub request_id: String,
    /// The revision the caller read, when it read one.
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

impl Mutation {
    /// Refuses a request id outside its bounds: absent, empty, over
    /// [`MAX_REQUEST_ID_BYTES`], or carrying a control character.
    pub fn validated(&self) -> Result<&str, Refusal> {
        let id = self.request_id.as_str();
        if id.is_empty() {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::host::REQUEST_ID_REQUIRED,
                "every mutation carries a `request_id`",
            ));
        }
        if id.len() > MAX_REQUEST_ID_BYTES {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::host::REQUEST_ID_REQUIRED,
                format!("`request_id` is longer than {MAX_REQUEST_ID_BYTES} bytes"),
            ));
        }
        if id.chars().any(char::is_control) {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::host::REQUEST_ID_REQUIRED,
                "`request_id` carries a control character",
            ));
        }
        Ok(id)
    }
}

/// Where the audit trail recorded a mutation. `seq` and `digest` arrive with the sealed trail
/// (WP-3.5, WP-3.7): until then they are absent, never invented (owner decision, 2026-10-06).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReference {
    /// The trail that recorded the event.
    pub trail: String,
    /// The event's position in the trail, once the trail numbers them.
    pub seq: Option<u64>,
    /// The event's digest, once the trail seals them.
    pub digest: Option<String>,
}

/// What every mutation answers: the contract's `{operation_id, revision, audit}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// This process's name for the mutation as applied; minted once, replayed with the result.
    pub operation_id: String,
    /// The revision the mutation produced.
    pub revision: u64,
    /// Where the audit trail recorded it.
    pub audit: AuditReference,
}

/// What the composition hands the facade: everything it serves with, built once in the
/// composition root.
pub struct Composition {
    /// The Host's authorization: every route decides with it.
    pub authorization: Arc<Authorization>,
    /// The grant store, when a volume holds one; without it the grant mutations are
    /// `grant_store_unavailable`.
    pub store: Option<Arc<GrantStore>>,
    /// The durable request-id replay window and the server-held plans.
    pub replay: Replay,
    /// The key rings this process composes, `host.identity` among them when the identity is
    /// open (WP-3.1).
    pub keys: Arc<crate::keys::registry::Registry>,
    /// The lifecycle the status route reports.
    pub health: Health,
    /// The assurance profile the volume runs under.
    pub assurance: Assurance,
    /// The effective configuration, masked.
    pub effective: Effective,
    /// The name of the audit trail receipts point at.
    pub trail: String,
    /// The security-mutation engine every mutation runs through (WP-3.6): its journal, its
    /// audit records and its idempotent answers. Without it the mutations are refused.
    pub mutations: Option<Arc<Mutations>>,
    /// The Host identity (WP-2.2); without it the identity routes are `identity_unavailable`.
    pub identity: Option<Arc<crate::identity::Identity>>,
    /// The Host's time guard: grant expiry and the times receipts carry (WP-2.12).
    pub time: Arc<crate::time::TimeGuard>,
    /// Peer Host sessions on the listener (WP-2.3).
    pub peer_sessions: sessions::PeerSessions,
}

/// The Host API facade: one instance per process, shared by both transports.
pub struct HostApi {
    authorization: Arc<Authorization>,
    store: Option<Arc<GrantStore>>,
    replay: Replay,
    bounds: Bounds,
    keys: Arc<crate::keys::registry::Registry>,
    health: Health,
    assurance: Assurance,
    effective: Effective,
    trail: String,
    mutations: Option<Arc<Mutations>>,
    identity: Option<Arc<crate::identity::Identity>>,
    time: Arc<crate::time::TimeGuard>,
    peer_sessions: sessions::PeerSessions,
}

impl std::fmt::Debug for HostApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostApi")
            .field("store", &self.store.is_some())
            .field("rings", &self.keys.ids())
            .finish_non_exhaustive()
    }
}

impl HostApi {
    /// Builds the facade. For composition roots and tests only.
    pub fn new(composition: Composition) -> Self {
        Self {
            authorization: composition.authorization,
            store: composition.store,
            replay: composition.replay,
            bounds: Bounds::default(),
            keys: composition.keys,
            health: composition.health,
            assurance: composition.assurance,
            effective: composition.effective,
            trail: composition.trail,
            mutations: composition.mutations,
            identity: composition.identity,
            time: composition.time,
            peer_sessions: composition.peer_sessions,
        }
    }

    /// Whether `actor` may do `operation` on the Host itself, with the principal it acts as.
    /// Every route starts here; the per-principal bounds are charged to the principal it names.
    fn admit(&self, actor: &Actor, operation: &str) -> Result<Admitted<'_>, Refusal> {
        self.authorization
            .authorize(actor, operation, &Resource::host())?;
        let principal = actor.principal()?;
        let permit = self.bounds.admit(&principal)?;
        Ok(Admitted {
            principal,
            _permit: permit,
        })
    }

    /// The grant store, or the refusal a mutation without one answers.
    fn store(&self) -> Result<&Arc<GrantStore>, Refusal> {
        self.store.as_ref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::host::GRANT_STORE_UNAVAILABLE,
                "no grant store is open on this process",
            )
        })
    }

    /// The mutation engine, or the refusal a mutation without one answers.
    fn mutations(&self) -> Result<&Arc<Mutations>, Refusal> {
        self.mutations.as_ref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::host::REPLAY_UNAVAILABLE,
                "no mutation journal is open on this process: nothing was applied",
            )
        })
    }

    /// Runs one grant mutation of `principal` through the transaction (WP-3.6): once per
    /// `(principal, request id)` inside the window, the same request answered with what the
    /// first attempt committed, across a restart; the same request id under another request
    /// refused. `check` validates against the current state once a retry is answered and before
    /// the intent; `apply` is the domain mutation; `reconciled` rebuilds the answer of an
    /// operation recovery committed without one, from the domain's state.
    #[allow(clippy::too_many_arguments)]
    fn transact<T, R>(
        &self,
        domain: &'static str,
        principal: &Principal,
        operation: &'static str,
        action: &'static str,
        mutation: &Mutation,
        request: &R,
        target: Option<String>,
        check: impl FnOnce() -> Result<(), Refusal>,
        apply: impl FnOnce(&Applying<'_>) -> Result<mutation::Applied<T>, Failure<Refusal>>,
        reconciled: impl FnOnce(OperationId, u64, Option<String>) -> Result<T, Refusal>,
    ) -> Result<T, Refusal>
    where
        T: Serialize + serde::de::DeserializeOwned,
        R: Serialize,
    {
        let mutations = self.mutations()?;
        let request_id = mutation.validated()?;
        let digest = replay::digest_of(request)?;
        // Held from here to the answer, across both windows.
        let _in_flight = self.replay.begin(principal, request_id)?;
        // An answer the replay journal recorded before WP-3.6 answers until its window ends.
        if let Some(stored) = self
            .replay
            .lookup::<T>(principal, request_id, operation, &digest)?
        {
            return Ok(stored);
        }
        let outcome = mutations.run_checked(
            Begin {
                domain,
                operation,
                action,
                initiator: Initiator::Principal(principal.as_str().to_owned()),
                request: Some(RequestKey {
                    request_id: request_id.to_owned(),
                    digest,
                }),
                target,
            },
            check,
            apply,
        );
        match outcome {
            Ok(Outcome::Applied(value)) => Ok(value),
            Ok(Outcome::Replayed(value)) => {
                tracing::debug!(
                    event.name = "host.replayed",
                    component = COMPONENT,
                    operation = operation,
                    "a retried mutation was answered from the replay window"
                );
                Ok(value)
            }
            Ok(Outcome::Reconciled {
                operation_id,
                revision,
                target,
            }) => reconciled(operation_id, revision, target),
            Err(error) => Err(refusal_of_mutation(operation, error)),
        }
    }

    /// Mints the receipt of the operation `operation_id`, which produced `revision`.
    fn receipt(&self, operation_id: OperationId, revision: u64) -> Receipt {
        Receipt {
            operation_id: operation_id.to_string(),
            revision,
            audit: AuditReference {
                trail: self.trail.clone(),
                seq: None,
                digest: None,
            },
        }
    }
}

/// The refusal of a mutation the engine did not end applied.
fn refusal_of_mutation(operation: &str, error: MutationError<Refusal>) -> Refusal {
    match error {
        MutationError::Refused(refusal) => refusal,
        MutationError::RequestIdReused(detail) => {
            Refusal::new(ErrorClass::Conflict, codes::host::REQUEST_ID_REUSED, detail)
        }
        MutationError::AuditUnavailable(detail) => {
            tracing::error!(
                event.name = "host.audit_unavailable",
                component = COMPONENT,
                operation = operation,
                error = %detail,
                "a security mutation was refused: the audit trail cannot record it"
            );
            Refusal::Api(
                ApiError::new(
                    ErrorClass::Unavailable,
                    codes::host::AUDIT_UNAVAILABLE,
                    "the audit trail cannot record security mutations: nothing was applied",
                )
                .with_internal(detail),
            )
        }
        MutationError::Unrecorded(detail) => {
            tracing::error!(
                event.name = "host.mutation_unrecorded",
                component = COMPONENT,
                operation = operation,
                error = %detail,
                "a Host mutation was applied and its record could not be written"
            );
            Refusal::Api(
                ApiError::new(
                    ErrorClass::Internal,
                    codes::host::MUTATION_UNRECORDED,
                    "the mutation may have been applied and its record could not be written: read \
                     the current state before retrying",
                )
                .with_internal(detail),
            )
        }
        MutationError::Indeterminate(refusal) => {
            let detail = refusal
                .error()
                .map_or_else(|| format!("{refusal:?}"), ToString::to_string);
            tracing::error!(
                event.name = "host.mutation_indeterminate",
                component = COMPONENT,
                operation = operation,
                error = %detail,
                "a Host mutation may have been applied; the next start resolves it"
            );
            Refusal::Api(
                ApiError::new(
                    ErrorClass::Internal,
                    codes::host::MUTATION_UNRECORDED,
                    "the mutation may have been applied and could not be recorded: read the \
                     current state before retrying",
                )
                .with_internal(detail),
            )
        }
        MutationError::Unavailable(detail) => Refusal::Api(
            ApiError::new(
                ErrorClass::Unavailable,
                codes::host::REPLAY_UNAVAILABLE,
                "the mutation journal is unavailable before the mutation: nothing was applied",
            )
            .with_internal(detail),
        ),
    }
}

/// An admitted caller: the principal it acts as, holding its concurrency permit.
struct Admitted<'a> {
    principal: Principal,
    /// Held for the life of the request; dropping it releases the slot.
    _permit: bounds::Permit<'a>,
}

#[cfg(test)]
pub(crate) mod testing {
    //! A facade over a scratch volume, for the tests of every operation.

    use std::sync::Arc;

    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::authz::{ActorContext, Credential, Selector, operations};

    use super::*;
    use crate::authz::{GrantStore, Issue, PublicGrant};
    use crate::operations::grants::Grants;
    use crate::operations::mutation::Projection;
    use crate::storage::volume::Volume;

    /// One audit record as the facade's tests read it: action, subject, target and phase.
    pub(crate) type Recorded = (String, String, Option<String>, Option<&'static str>);

    /// The audit trail of the facade's tests: remembers every record, or refuses them all.
    #[derive(Default)]
    pub(crate) struct Recording {
        pub(crate) events: std::sync::Mutex<Vec<Recorded>>,
        /// Every record refused.
        pub(crate) refuse: std::sync::atomic::AtomicBool,
        /// The records of this phase refused.
        pub(crate) refuse_phase: std::sync::Mutex<Option<&'static str>>,
        /// Run once, when the next intent record is written: how a test fails a later step.
        #[allow(clippy::type_complexity)]
        pub(crate) on_intent: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl Projection for Recording {
        fn project(&self, event: &permguard_core::AuditEvent<'_>) -> Result<(), String> {
            let phase = event.operation().map(|(_, phase)| phase.as_str());
            let refused_phase = *self
                .refuse_phase
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.refuse.load(std::sync::atomic::Ordering::SeqCst)
                || (refused_phase.is_some() && refused_phase == phase)
            {
                return Err("the trail is full".to_owned());
            }
            if phase == Some("intent")
                && let Some(hook) = self
                    .on_intent
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
            {
                hook();
            }
            let subject = match event.subject() {
                permguard_core::Subject::Principal(principal) => format!("principal:{principal}"),
                permguard_core::Subject::System(system) => format!("system:{system}"),
                other => other.to_string(),
            };
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((
                    event.action().to_owned(),
                    subject,
                    event.target().map(str::to_owned),
                    phase,
                ));
            Ok(())
        }
    }

    pub(crate) fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-host-api-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    pub(crate) fn actor(name: &str) -> Actor {
        Actor::Authenticated(ActorContext::new(
            Principal::new(name).expect("a principal"),
            Credential::SanUri,
            None,
        ))
    }

    pub(crate) const ADMIN: &str = "spiffe://acme/operators/root";

    /// A facade whose store holds one administrator with every Host operation, on a volume that
    /// outlives the test (the claim is leaked on purpose: the store keeps the directory open).
    pub(crate) fn facade(tag: &str) -> HostApi {
        facade_with(tag, Vec::new())
    }

    pub(crate) fn facade_with(tag: &str, rings: Vec<&'static str>) -> HostApi {
        let root = scratch(tag);
        let (api, _, volume) = reopen(&root, rings);
        std::mem::forget(volume);
        api
    }

    /// Opens, or reopens, a facade on `root`, so a test can watch what survives a restart: the
    /// volume is handed back, and dropping it releases the lock for the next open.
    pub(crate) fn reopen(
        root: &std::path::Path,
        rings: Vec<&'static str>,
    ) -> (HostApi, Arc<GrantStore>, Volume) {
        reopen_with(root, rings, Arc::new(Recording::default()))
    }

    /// [`reopen`], recording the audit trail in `trail`.
    pub(crate) fn reopen_with(
        root: &std::path::Path,
        rings: Vec<&'static str>,
        trail: Arc<Recording>,
    ) -> (HostApi, Arc<GrantStore>, Volume) {
        let volume =
            Volume::claim(root, AssuranceProfile::Development).expect("the volume is claimed");
        let (store, _) = GrantStore::open(&volume).expect("the grant store opens");
        let time = Arc::new(crate::time::TimeGuard::system(
            std::time::Duration::from_secs(30),
        ));
        let mutations = Arc::new(
            Mutations::open(&volume, trail, Arc::clone(&time)).expect("the mutation journal opens"),
        );
        mutations
            .recover(&Grants(&store))
            .expect("the mutation journal recovers");
        let provider: Arc<dyn crate::keys::KeyProvider> =
            Arc::new(crate::keys::FileKeyProvider::new(
                crate::identity::directories(&volume)
                    .expect("the identity")
                    .1,
            ));
        let identity = Arc::new(
            if crate::identity::is_provisioned(&volume).expect("read") {
                crate::identity::Identity::open(&volume, provider)
            } else {
                crate::identity::Identity::provision(
                    &volume,
                    provider,
                    crate::identity::Suite::Ed25519Sha256V1,
                    crate::authz::store::now(),
                    crate::authz::store::now() * 1000,
                )
            }
            .expect("the identity opens"),
        );
        mutations
            .recover(&crate::identity::Identities(&identity))
            .expect("the identity recovers");
        // The rings a test asks for, each on the volume and bound by the identity (WP-3.1).
        let rings: Vec<Arc<crate::keys::ring::Ring>> = rings
            .into_iter()
            .map(|id| {
                let ring = Arc::new(
                    crate::keys::ring::Ring::open(
                        &volume,
                        id,
                        crate::identity::Suite::Ed25519Sha256V1,
                        crate::keys::ring::Policy {
                            publish_ahead: std::time::Duration::from_secs(600),
                            rotate_every: std::time::Duration::from_secs(3600),
                            retain: std::time::Duration::from_secs(7200),
                        },
                        Arc::clone(&time),
                    )
                    .expect("the ring opens")
                    .with_binder(identity.clone()),
                );
                permguard_core::KeyManager::maintain(ring.as_ref())
                    .expect("the ring is maintained");
                ring
            })
            .collect();
        let registry = crate::keys::registry::Registry::new(Some(Arc::clone(&identity)), rings);
        mutations
            .recover(&registry)
            .expect("the key mutations recover");
        let admin = Principal::new(ADMIN).expect("a principal");
        if !store
            .records()
            .iter()
            .any(|record| record.principal_id == admin)
        {
            crate::operations::grants::issue(
                &mutations,
                &store,
                Initiator::System("test".to_owned()),
                Issue {
                    principal: admin,
                    operations: operations::ALL
                        .iter()
                        .map(|operation| (*operation).to_owned())
                        .collect(),
                    selector: Selector::under(Resource::host()),
                    resource_types: vec!["*".to_owned()],
                    constraints: Default::default(),
                    issued_by: "test".to_owned(),
                    expires_at: None,
                },
                crate::authz::store::now(),
            )
            .expect("the administrator is issued");
        }
        let (replay, _) =
            Replay::open(&volume, crate::authz::store::now()).expect("the replay journal opens");
        let authorization = Arc::new(Authorization::new(
            Arc::clone(&store),
            &[PublicGrant::new(
                &[operations::KEYS_READ],
                Selector::exactly(Resource::host()),
            )],
        ));
        let api = HostApi::new(Composition {
            authorization,
            store: Some(Arc::clone(&store)),
            replay,
            keys: Arc::new(registry),
            health: Health::new(),
            assurance: Assurance::of(
                &permguard_core::assurance::Assurance::new(
                    permguard_core::assurance::AssuranceProfile::Development,
                    [],
                )
                .report(&[]),
            ),
            effective: Effective {
                revision: 0,
                settings: Vec::new(),
            },
            trail: "audit".to_owned(),
            mutations: Some(mutations),
            identity: Some(identity),
            time,
            peer_sessions: sessions::PeerSessions::none(),
        });
        (api, store, volume)
    }

    pub(crate) fn admin() -> Actor {
        actor(ADMIN)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::testing::{actor, admin, facade_with};
    use super::*;

    #[test]
    fn a_request_id_is_bounded_and_printable() {
        let short = Mutation {
            request_id: "r-1".to_owned(),
            expected_revision: None,
        };
        assert_eq!(short.validated().expect("fits"), "r-1");
        for bad in [
            String::new(),
            "x".repeat(MAX_REQUEST_ID_BYTES + 1),
            "a\u{7}b".to_owned(),
        ] {
            let refused = Mutation {
                request_id: bad,
                expected_revision: None,
            }
            .validated()
            .expect_err("refused");
            let error = refused.error().expect("a domain refusal");
            assert_eq!(error.code(), codes::host::REQUEST_ID_REQUIRED);
            assert_eq!(error.http_status(), 400);
        }
    }

    #[test]
    fn the_ring_bindings_are_read_under_identity_read() {
        let api = facade_with("bindings", vec![crate::keys::ring::DATA_ATTEST]);
        let refused = api
            .ring_bindings(&actor("spiffe://acme/nobody"))
            .expect_err("no grant");
        assert!(matches!(refused, Refusal::Denied(denial) if denial.http_status() == 403));
        let refused = api.ring_bindings(&Actor::Anonymous).expect_err("nobody");
        assert!(matches!(refused, Refusal::Denied(denial) if denial.http_status() == 401));
        let bindings = api.ring_bindings(&admin()).expect("served");
        assert_eq!(bindings.bindings.len(), 1);
        assert_eq!(bindings.bindings[0].ring, crate::keys::ring::DATA_ATTEST);
        assert_eq!(bindings.bindings[0].epoch, 1);
    }
}
