// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The request-id replay window and the server-held plans: the contract their store keeps
//! ([`ReplayStore`], `1-architecture/8` Store contracts) and what the Host API does with it
//! ([`Replay`]).
//!
//! Every mutation applied before WP-3.6 was recorded as `{principal, request_id, operation,
//! digest, result}`, so a retry inside the window, from the same principal with the same
//! request, is answered with the stored result, across a restart. The window is [`WINDOW`] long
//! and holds at most [`PER_PRINCIPAL`] results per principal. Since WP-3.6 the answers a retry
//! learns are the mutation journal's commits; the results a store holds from before answer until
//! their window ends, and no new one is written.
//!
//! A plan of a two-step mutation (`revoke/plan`, then `revoke/run`) lives in the same store: the
//! plan step writes `{plan_id, operation, target, revision, digest, expires, principal}`, the
//! run step consumes it once, each inside its operation of the security-mutation transaction
//! (WP-3.6). Since WP-3.9 a plan also keeps the receipt the plan step answered, which the run
//! must present byte for byte, how many approvals it requires and each approval the Host attested;
//! a consumed plan is kept, marked, until it would have expired, so the plans store lists it.
//! Every plan, consumed or not, is kept one [`WINDOW`] past its expiry, so the plans store lists
//! it `expired` for that long before it goes.
//!
//! An approval, and a plan the offline reset consumes ahead of its change, are operations of the
//! [`DOMAIN`] domain, which this store is: each writes its operation id beside what it records,
//! so recovery commits an operation whose record is durable and fails one whose record is not.
//!
//! What a store does not hold is the request in flight: a `(principal, request_id)` pair is
//! taken in this process for the time of one mutation ([`Replay::begin`]).

use permguard_core::encoding::hex;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use permguard_core::authz::Principal;
use permguard_core::{ErrorClass, codes};

use super::Refusal;
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Applying, Domain, Observed};

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

pub use files::{DIRECTORY, JOURNAL};

/// The mutation domain of approvals and of plans consumed ahead of their change (WP-3.9).
pub const DOMAIN: &str = "plans";

/// How long a stored result answers a retry.
pub const WINDOW: Duration = Duration::from_secs(10 * 60);
/// How many results one principal may hold inside the window.
pub const PER_PRINCIPAL: usize = 4096;
/// How long a plan may be run after it was made.
pub const PLAN_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// What the store refuses with.
#[derive(Debug)]
pub enum ReplayError {
    /// The store did not answer, or could not be written: nothing is known of the change. It
    /// carries what the store said, as the store said it.
    Unavailable(Box<dyn std::error::Error + Send + Sync>),
    /// A record does not decode, or a result does not deserialize as its operation's answer.
    Malformed(String),
    /// The plan to consume is not held for its principal.
    PlanUnknown,
    /// The plan to consume was consumed already: a plan is run once.
    PlanConsumed,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(error) => write!(f, "{error}"),
            Self::Malformed(detail) => f.write_str(detail),
            Self::PlanUnknown => f.write_str("no plan of that id is held for this principal"),
            Self::PlanConsumed => f.write_str("this plan was already run"),
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<ReplayError> for Refusal {
    fn from(error: ReplayError) -> Self {
        match error {
            ReplayError::PlanUnknown => Refusal::new(
                ErrorClass::NotFound,
                codes::host::PLAN_UNKNOWN,
                error.to_string(),
            ),
            ReplayError::PlanConsumed => Refusal::new(
                ErrorClass::Conflict,
                codes::host::PLAN_EXPIRED,
                error.to_string(),
            ),
            ReplayError::Unavailable(_) | ReplayError::Malformed(_) => Refusal::Api(
                permguard_core::ApiError::new(
                    ErrorClass::Unavailable,
                    codes::host::REPLAY_UNAVAILABLE,
                    "the replay journal is unavailable before the mutation: nothing was applied",
                )
                .with_internal(error.to_string()),
            ),
        }
    }
}

/// A result a store holds from before WP-3.6: what a retry of its request is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub operation: String,
    pub digest: String,
    pub result: serde_json::Value,
}

/// A server-held plan: what `revoke/plan` wrote and `revoke/run` presents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub plan_id: String,
    pub operation: String,
    pub target: String,
    pub revision: u64,
    pub digest: String,
    pub expires: u64,
    pub principal: String,
    /// The operation as the receipt names it (WP-3.9); empty for a plan made before.
    #[serde(default)]
    pub kind: String,
    /// The receipt the plan step answered, base64url, which the run presents back.
    #[serde(default)]
    pub receipt: String,
    #[serde(default)]
    pub approvals_required: u64,
    #[serde(default)]
    pub approvals: Vec<PlanApproval>,
    #[serde(default)]
    pub created_at: u64,
}

/// One principal's approval of a plan, as the Host attested it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanApproval {
    pub principal: String,
    pub approved_at: u64,
    /// COSE_Sign1 `permguard.operation.approval.v1`, base64url.
    pub envelope: String,
    /// The operation that recorded it, which recovery looks for.
    #[serde(default)]
    pub operation_id: String,
    /// Where the approver's access token stands, read again when the plan runs: none for an
    /// approval made by certificate, or before approvals recorded it (BUG-0099).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenEntry>,
}

/// An access token's entry in its issuer's status list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenEntry {
    /// The list's `uri`.
    pub uri: String,
    /// The token's index in it.
    pub index: u64,
}

/// What an approval is decided by: the plan as it stands and whether it was run, read by the
/// store in the step that records the approval the decision answers.
pub type Decide<'a> = &'a dyn Fn(&Plan, bool) -> Result<PlanApproval, Refusal>;

/// Why an approval was not recorded.
#[derive(Debug)]
pub enum Unapproved {
    /// The decision refused it: nothing was written.
    Refused(Refusal),
    /// The store failed. When it is [`ReplayError::Unavailable`] the approval may be recorded all
    /// the same, and the operation's recovery says whether it is.
    Store(ReplayError),
}

impl From<ReplayError> for Unapproved {
    fn from(error: ReplayError) -> Self {
        Self::Store(error)
    }
}

/// The replay window and the plans of one Host: the only way its code reads and changes them
/// (`1-architecture/8` Store contracts).
///
/// A call holds one complete rule: the read that decides an approval or a consumption and the
/// record it writes are one step for every other change of the store.
pub trait ReplayStore: Send + Sync {
    /// The result held of `(principal, request_id)`, when one is inside the window at `now`.
    fn result(
        &self,
        principal: &str,
        request_id: &str,
        now: u64,
    ) -> Result<Option<Stored>, ReplayError>;

    /// How many results are held.
    fn held(&self) -> Result<usize, ReplayError>;

    /// Keeps `plan`, inside the operation `applying`.
    fn write_plan(&self, applying: &Applying<'_>, plan: &Plan) -> Result<(), ReplayError>;

    /// The plan `plan_id` of `principal`, and whether it was run.
    fn plan(&self, principal: &str, plan_id: &str) -> Result<Option<(Plan, bool)>, ReplayError>;

    /// The plan `plan_id`, whoever made it, and whether it was run.
    fn find(&self, plan_id: &str) -> Result<Option<(Plan, bool)>, ReplayError>;

    /// Every plan held, and whether it was run.
    fn plans(&self) -> Result<Vec<(Plan, bool)>, ReplayError>;

    /// Records the approval `decide` answers for the plan `plan_id`, inside the operation
    /// `applying`, and answers the plan with it; `None`, and nothing decided, when no plan of
    /// that id is held. `decide` is given the plan as it stands in the step that records its
    /// answer: no approval is recorded for a plan another change has moved since it was judged.
    /// A refusal of `decide` records nothing, and is told apart from a store that failed.
    fn approve(
        &self,
        applying: &Applying<'_>,
        plan_id: &str,
        decide: Decide<'_>,
    ) -> Result<Option<Plan>, Unapproved>;

    /// Consumes the plan `plan_id` of `principal`, inside the operation `applying`: once. A plan
    /// consumed already is [`ReplayError::PlanConsumed`], one that is not held
    /// [`ReplayError::PlanUnknown`], and neither writes anything.
    fn consume(
        &self,
        applying: &Applying<'_>,
        principal: &str,
        plan_id: &str,
    ) -> Result<(), ReplayError>;

    /// What the operation `operation_id` on `target` left, for recovery: an approval shows as
    /// the plan `target` holding one recorded by the operation; a plan consumed ahead of its
    /// change, `consume:<plan_id>`, as that plan consumed.
    fn operation(
        &self,
        operation_id: &OperationId,
        target: Option<&str>,
    ) -> Result<Option<Observed>, ReplayError>;
}

/// The replay window as the Host API uses it: a store, the requests in flight in this process
/// and the clock the window is measured by.
pub struct Replay {
    store: Arc<dyn ReplayStore>,
    /// The `(principal, request_id)` pairs with a mutation in flight: a second arrival with the
    /// same pair while the first is between its lookup and its record is refused, so two
    /// simultaneous retries cannot both apply.
    in_flight: Mutex<BTreeSet<(String, String)>>,
    /// Where the window is measured from (WP-2.12).
    time: Arc<crate::time::TimeGuard>,
}

/// One mutation in flight; dropping it lets the next arrival with the same pair in.
#[derive(Debug)]
pub struct InFlight<'a> {
    replay: &'a Replay,
    key: (String, String),
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.replay
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

impl std::fmt::Debug for Replay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replay").finish_non_exhaustive()
    }
}

impl Replay {
    /// The replay window over `store`, measured by the system clock until [`Self::with_time`].
    pub fn new(store: Arc<dyn ReplayStore>) -> Self {
        Self {
            store,
            in_flight: Mutex::new(BTreeSet::new()),
            time: Arc::new(crate::time::TimeGuard::system(
                permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
            )),
        }
    }

    /// Takes the `(principal, request_id)` pair for the duration of one mutation, or refuses a
    /// second arrival while the first is in flight: it retries once the first has answered.
    pub fn begin(&self, principal: &Principal, request_id: &str) -> Result<InFlight<'_>, Refusal> {
        let key = (principal.as_str().to_owned(), request_id.to_owned());
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !in_flight.insert(key.clone()) {
            // Retryable, and said so by its class and its own code: `request_id_reused` means
            // "never retry this", and the same request in flight is the opposite (BUG-0169).
            return Err(Refusal::new(
                ErrorClass::Unavailable,
                codes::host::REQUEST_IN_FLIGHT,
                "a mutation with this request id is in flight; retry once it has answered",
            ));
        }
        Ok(InFlight { replay: self, key })
    }

    /// Measures the window against `time`, the Host's guard, instead of a guard of its own.
    pub fn with_time(mut self, time: Arc<crate::time::TimeGuard>) -> Self {
        self.time = time;
        self
    }

    /// The stored result of `(principal, request_id)` as `T`, when one is held inside the window
    /// for the same `operation` and the same request `digest`; the same request id under
    /// another operation or request is `request_id_reused`.
    pub fn lookup<T: DeserializeOwned>(
        &self,
        principal: &Principal,
        request_id: &str,
        operation: &str,
        digest: &str,
    ) -> Result<Option<T>, Refusal> {
        let now = self.time.now_secs();
        let Some(stored) = self.store.result(principal.as_str(), request_id, now)? else {
            return Ok(None);
        };
        if stored.operation != operation || stored.digest != digest {
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::REQUEST_ID_REUSED,
                "this request id was already used for a different mutation inside the replay window",
            ));
        }
        let result = serde_json::from_value(stored.result).map_err(|error| {
            ReplayError::Malformed(format!(
                "a stored result of `{operation}` does not read as its answer: {error}"
            ))
        })?;
        Ok(Some(result))
    }

    /// Writes a plan, durably, inside the operation `applying` names (WP-3.6).
    pub fn plan(&self, applying: &Applying<'_>, plan: Plan) -> Result<(), Refusal> {
        Ok(self.store.write_plan(applying, &plan)?)
    }

    /// The plan `plan_id` of `principal`, when it is held, not yet consumed and not expired at
    /// `now`: `plan_unknown` otherwise, `plan_expired` when it was run or has aged out.
    pub fn plan_of(&self, principal: &Principal, plan_id: &str, now: u64) -> Result<Plan, Refusal> {
        let Some((plan, consumed)) = self.store.plan(principal.as_str(), plan_id)? else {
            return Err(ReplayError::PlanUnknown.into());
        };
        if consumed {
            return Err(ReplayError::PlanConsumed.into());
        }
        if plan.expires <= now {
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::PLAN_EXPIRED,
                "this plan has expired; plan again",
            ));
        }
        Ok(plan)
    }

    /// Consumes `plan_id` of `principal`, durably, inside the run's operation, once: a second
    /// consumption is refused, and a second run finds the plan `plan_expired`. The caller decides
    /// what a failure here means when the plan's mutation is already applied.
    pub fn consume(
        &self,
        applying: &Applying<'_>,
        principal: &Principal,
        plan_id: &str,
    ) -> Result<(), ReplayError> {
        self.store.consume(applying, principal.as_str(), plan_id)
    }

    /// Records the approval `decide` answers for the plan `plan_id`, durably, inside the
    /// approval's operation (WP-3.9), and answers the plan with it; `None` when no plan of that
    /// id is held. `decide` judges the plan in the step that records its answer.
    pub fn approve(
        &self,
        applying: &Applying<'_>,
        plan_id: &str,
        decide: Decide<'_>,
    ) -> Result<Option<Plan>, Unapproved> {
        self.store.approve(applying, plan_id, decide)
    }

    /// The plan `plan_id`, whoever made it, and whether it was run: what an approval reads.
    pub fn find(&self, plan_id: &str) -> Result<Option<(Plan, bool)>, ReplayError> {
        self.store.find(plan_id)
    }

    /// Every plan held, made since WP-3.9, and whether it was run: what the plans store lists.
    pub fn plans(&self) -> Result<Vec<(Plan, bool)>, ReplayError> {
        let mut plans = self.store.plans()?;
        plans.retain(|(plan, _)| !plan.kind.is_empty());
        Ok(plans)
    }

    /// How many results are held, for the tests and the start-up record.
    pub fn held(&self) -> Result<usize, ReplayError> {
        self.store.held()
    }
}

/// Whether a plan expiring at `expires`, or its consumed marker, is still kept at `now`: one
/// [`WINDOW`] past its expiry, listed `expired` meanwhile.
pub(crate) fn kept(expires: u64, now: u64) -> bool {
    expires.saturating_add(WINDOW.as_secs()) > now
}

impl Domain for Replay {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(
        &self,
        operation_id: &OperationId,
        target: Option<&str>,
    ) -> Result<Option<Observed>, String> {
        // A store that does not answer is not an operation that is not there: it stops recovery.
        self.store
            .operation(operation_id, target)
            .map_err(|error| error.to_string())
    }
}

/// The digest a mutation's request is remembered by: SHA-256 over its JSON, hex.
pub fn digest_of<R: Serialize>(request: &R) -> Result<String, Refusal> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        ReplayError::Malformed(format!(
            "a request does not serialize for its digest: {error}"
        ))
    })?;
    Ok(hex(&Sha256::digest(&bytes)))
}

/// A fresh identifier: 16 bytes from the OS CSPRNG, hex. The one generator the process already
/// uses; a failure is the OS refusing random bytes, which nothing here can recover from, so the
/// mutation is refused rather than named by an id that is not random.
pub fn mint_id() -> Result<String, Refusal> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        tracing::error!(
            event.name = "host.random_unavailable",
            component = super::COMPONENT,
            "the OS random source refused to fill an identifier"
        );
        return Err(Refusal::new(
            ErrorClass::Internal,
            codes::common::INTERNAL,
            "the random source refused an identifier; the mutation was not applied",
        ));
    }
    Ok(hex(&bytes))
}

#[cfg(test)]
mod tests;
