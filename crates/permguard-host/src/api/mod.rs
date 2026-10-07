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
pub mod keys;
pub mod replay;
pub mod status;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, Principal, Resource, operations};
use permguard_core::keys::KeyManager;
use permguard_core::{AccessDenial, ApiError, AuditRecorder, ErrorClass, Health, codes};

use crate::authz::{Authorization, GrantStore};

pub use bounds::Bounds;
pub use config::{Effective, Setting};
pub use grants::{CreateGrant, GrantView, Grants, PlanRevoke, Planned, Revoked, RunRevoke};
pub use keys::{RingSummary, RingView, Rings};
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
    /// The key rings this process composes, by their ring id.
    pub rings: Vec<(String, Arc<dyn KeyManager>)>,
    /// The lifecycle the status route reports.
    pub health: Health,
    /// The assurance profile the volume runs under.
    pub assurance: Assurance,
    /// The effective configuration, masked.
    pub effective: Effective,
    /// The name of the audit trail receipts point at.
    pub trail: String,
    /// The recorder every mutation writes its audit event through, when the composition has one.
    pub recorder: Option<AuditRecorder>,
    /// The Host's time guard: grant expiry and the times receipts carry (WP-2.12).
    pub time: Arc<crate::time::TimeGuard>,
}

/// The Host API facade: one instance per process, shared by both transports.
pub struct HostApi {
    authorization: Arc<Authorization>,
    store: Option<Arc<GrantStore>>,
    replay: Replay,
    bounds: Bounds,
    rings: Vec<(String, Arc<dyn KeyManager>)>,
    health: Health,
    assurance: Assurance,
    effective: Effective,
    trail: String,
    /// `pub(crate)` for the tests of the mutations, which compose their own recorder.
    pub(crate) recorder: Option<AuditRecorder>,
    time: Arc<crate::time::TimeGuard>,
}

impl std::fmt::Debug for HostApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostApi")
            .field("store", &self.store.is_some())
            .field("rings", &self.rings.len())
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
            rings: composition.rings,
            health: composition.health,
            assurance: composition.assurance,
            effective: composition.effective,
            trail: composition.trail,
            recorder: composition.recorder,
            time: composition.time,
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

    /// `GET /host/v1/identity`: the signed identity document arrives with WP-2.2. Until then
    /// the route authorizes and answers `not_served_yet`; the type says there is no answer yet.
    pub fn identity(&self, actor: &Actor) -> Result<std::convert::Infallible, Refusal> {
        let _admitted = self.admit(actor, operations::IDENTITY_READ)?;
        Err(Refusal::not_served_yet("the Host identity", "WP-2.2"))
    }

    /// `GET /host/v1/ring-bindings`: the signed bindings arrive with WP-2.3.
    pub fn ring_bindings(&self, actor: &Actor) -> Result<std::convert::Infallible, Refusal> {
        let _admitted = self.admit(actor, operations::IDENTITY_READ)?;
        Err(Refusal::not_served_yet("the ring bindings", "WP-2.3"))
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

    /// Runs `apply` once per `(principal, request id)` inside the replay window: a retry with
    /// the same operation and the same request is answered with what the first attempt
    /// answered, across a restart; the same request id under another request is refused.
    fn mutate<T, R>(
        &self,
        principal: &Principal,
        operation: &'static str,
        mutation: &Mutation,
        request: &R,
        apply: impl FnOnce(&str) -> Result<T, Refusal>,
    ) -> Result<Applied<T>, Refusal>
    where
        T: Serialize + serde::de::DeserializeOwned,
        R: Serialize,
    {
        let request_id = mutation.validated()?;
        let digest = replay::digest_of(request)?;
        // Held from here to the record: two simultaneous retries cannot both miss the window
        // and both apply; the second is refused and retries once the first has answered.
        let _in_flight = self.replay.begin(principal, request_id)?;
        if let Some(stored) = self
            .replay
            .lookup::<T>(principal, request_id, operation, &digest)?
        {
            tracing::debug!(
                event.name = "host.replayed",
                component = COMPONENT,
                operation = operation,
                "a retried mutation was answered from the replay window"
            );
            return Ok(Applied {
                value: stored,
                fresh: false,
            });
        }
        // The operation id is minted before anything is applied, so the one refusal minting can
        // produce comes while "not applied" is still true.
        let operation_id = replay::mint_id()?;
        let value = apply(&operation_id)?;
        self.replay
            .record(principal, request_id, operation, &digest, &value)
            .map_err(|error| unrecorded(operation, error))?;
        Ok(Applied { value, fresh: true })
    }

    /// Mints the receipt of a mutation that produced `revision`.
    fn receipt(&self, operation_id: &str, revision: u64) -> Receipt {
        Receipt {
            operation_id: operation_id.to_owned(),
            revision,
            audit: AuditReference {
                trail: self.trail.clone(),
                seq: None,
                digest: None,
            },
        }
    }
}

/// The refusal of a mutation that is applied and could not be recorded for replay: said as
/// such, never as "not applied", so a caller reads before it retries. `TODO(WP-3.6)`: the
/// mutation transaction makes the record and the mutation one durable step.
pub(crate) fn unrecorded(operation: &str, error: replay::ReplayError) -> Refusal {
    tracing::error!(
        event.name = "host.mutation_unrecorded",
        component = COMPONENT,
        operation = operation,
        error = %error,
        "a Host mutation was applied and the replay journal could not record it"
    );
    Refusal::Api(
        ApiError::new(
            ErrorClass::Internal,
            codes::host::MUTATION_UNRECORDED,
            "the mutation was applied and could not be recorded for replay: read the current \
             state before retrying, since a retry with this request id is not answered from the \
             window",
        )
        .with_internal(error.to_string()),
    )
}

/// What a mutation produced, and whether this call applied it or replayed it.
struct Applied<T> {
    value: T,
    fresh: bool,
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
    use permguard_core::authz::{ActorContext, Credential, Selector};

    use super::*;
    use crate::authz::{GrantStore, Issue, PublicGrant};
    use crate::storage::volume::Volume;

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

    pub(crate) fn facade_with(tag: &str, rings: Vec<(String, Arc<dyn KeyManager>)>) -> HostApi {
        let root = scratch(tag);
        let (api, _, volume) = reopen(&root, rings);
        std::mem::forget(volume);
        api
    }

    /// Opens, or reopens, a facade on `root`, so a test can watch what survives a restart: the
    /// volume is handed back, and dropping it releases the lock for the next open.
    pub(crate) fn reopen(
        root: &std::path::Path,
        rings: Vec<(String, Arc<dyn KeyManager>)>,
    ) -> (HostApi, Arc<GrantStore>, Volume) {
        let volume =
            Volume::claim(root, AssuranceProfile::Development).expect("the volume is claimed");
        let (store, _) = GrantStore::open(&volume).expect("the grant store opens");
        let admin = Principal::new(ADMIN).expect("a principal");
        if !store
            .records()
            .iter()
            .any(|record| record.principal_id == admin)
        {
            store
                .issue(
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
            rings,
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
            recorder: None,
            time: Arc::new(crate::time::TimeGuard::system(
                std::time::Duration::from_secs(30),
            )),
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

    use super::testing::{actor, admin, facade};
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
    fn the_stubs_authorize_before_they_say_they_are_not_served() {
        let api = facade("stubs");
        let refused = api
            .identity(&actor("spiffe://acme/nobody"))
            .expect_err("no grant");
        assert!(matches!(refused, Refusal::Denied(denial) if denial.http_status() == 403));
        let refused = api.identity(&Actor::Anonymous).expect_err("nobody");
        assert!(matches!(refused, Refusal::Denied(denial) if denial.http_status() == 401));
        let unavailable = api.identity(&admin()).expect_err("not served yet");
        let error = unavailable.error().expect("a domain refusal");
        assert_eq!(error.code(), codes::host::NOT_SERVED_YET);
        assert_eq!(error.http_status(), 503);
        let bindings = api.ring_bindings(&admin()).expect_err("not served yet");
        assert_eq!(
            bindings.error().expect("a domain refusal").code(),
            codes::host::NOT_SERVED_YET
        );
    }
}
