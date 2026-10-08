// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The grants of the Host API, under `authz.admin` on the Host: `GET /host/v1/grants`,
//! `POST /host/v1/grants`, and the two-step revocation `revoke/plan` then `revoke/run`.
//!
//! The plan step writes a server-held plan into the replay journal and answers its id and
//! digest; the run step presents both, and the plan is consumed once (owner decision,
//! 2026-10-06). `TODO(WP-3.9)`: the client-held COSE_Sign1 plan receipt and dual control.
//! Every mutation is one operation of the security-mutation transaction (WP-3.6): its intent,
//! its audit records and the answer a retry learns live in `host/audit/mutations/`, and the
//! revision a caller expects is compared under the grant journal's lock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use permguard_core::authz::{Actor, Principal, Selector, operations};
use permguard_core::{ErrorClass, codes};

use super::replay::{PLAN_LIFETIME, Plan, mint_id};
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::authz::{AuthzError, GrantId, GrantRecord, Issue, Status};
use crate::operations::grants::{
    AUDIT_ISSUED, AUDIT_REVOKE_PLANNED, AUDIT_REVOKED, CREATE, REVOKE_PLAN, REVOKE_RUN, failure,
};
use crate::operations::mutation::{Applied, Failure};

/// The operation a plan of a revocation names.
const REVOKE: &str = "grants.revoke";

/// One grant, as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    pub grant_id: String,
    pub principal: String,
    pub operations: Vec<String>,
    pub selector: String,
    pub resource_types: Vec<String>,
    pub constraints: BTreeMap<String, String>,
    pub revision: u64,
    /// `active`, `revoked` or `expired`.
    pub status: String,
    pub issued_by: String,
    /// RFC 3339.
    pub issued_at: String,
    /// RFC 3339, when the grant expires.
    pub expires_at: Option<String>,
}

impl From<GrantRecord> for GrantView {
    fn from(record: GrantRecord) -> Self {
        Self {
            grant_id: record.grant_id.to_string(),
            principal: record.principal_id.as_str().to_owned(),
            operations: record.operations,
            selector: record.selector.to_string(),
            resource_types: record.resource_types,
            constraints: record.constraints,
            revision: record.revision,
            status: record.status.as_str().to_owned(),
            issued_by: record.issued_by,
            issued_at: rfc3339(record.issued_at),
            expires_at: record.expires_at.map(rfc3339),
        }
    }
}

/// `GET /host/v1/grants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grants {
    /// The store revision the list was read at.
    pub revision: u64,
    pub grants: Vec<GrantView>,
}

/// `POST /host/v1/grants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGrant {
    /// Absent reads as empty, so the facade refuses it as `request_id_required` on both wires.
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    pub principal: String,
    pub operations: Vec<String>,
    pub selector: String,
    #[serde(default)]
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub constraints: BTreeMap<String, String>,
    /// RFC 3339.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// What a create answers: the receipt and the grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Created {
    pub receipt: Receipt,
    pub grant: GrantView,
}

/// `POST /host/v1/grants/{id}/revoke/plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRevoke {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

/// What a plan answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Planned {
    pub plan_id: String,
    pub plan_digest: String,
    /// RFC 3339: when the plan can no longer be run.
    pub expires: String,
    /// The grant revision the plan was made against.
    pub revision: u64,
}

/// `POST /host/v1/grants/{id}/revoke/run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRevoke {
    #[serde(default)]
    pub request_id: String,
    pub plan_id: String,
    pub plan_digest: String,
}

/// What a run answers: the receipt and the grant as revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoked {
    pub receipt: Receipt,
    pub grant: GrantView,
}

impl HostApi {
    /// `GET /host/v1/grants?principal&selector`.
    pub fn grants(
        &self,
        actor: &Actor,
        principal: Option<&str>,
        selector: Option<&str>,
    ) -> Result<Grants, Refusal> {
        let _admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let store = self.store()?;
        let mut grants: Vec<GrantView> = store
            .records()
            .into_iter()
            .filter(|record| principal.is_none_or(|wanted| record.principal_id.as_str() == wanted))
            .filter(|record| selector.is_none_or(|wanted| record.selector.to_string() == wanted))
            .map(GrantView::from)
            .collect();
        // In the order of their last transition, then by id: the store keys records by their
        // random id, and a list whose order depends on that is a list two readers cannot compare.
        grants.sort_by(|left, right| {
            (left.revision, &left.grant_id).cmp(&(right.revision, &right.grant_id))
        });
        Ok(Grants {
            revision: store.revision(),
            grants,
        })
    }

    /// `POST /host/v1/grants`.
    pub async fn create_grant(
        &self,
        actor: &Actor,
        create: CreateGrant,
    ) -> Result<Created, Refusal> {
        let admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let store = self.store()?;
        bounded(&create)?;
        let mutation = Mutation {
            request_id: create.request_id.clone(),
            expected_revision: create.expected_revision,
        };
        let now = self.time.now_secs();
        let issue = Issue {
            principal: Principal::new(create.principal.as_str())
                .map_err(|error| invalid(format!("`principal`: {error}")))?,
            operations: create.operations.clone(),
            selector: Selector::parse(&create.selector)
                .map_err(|error| invalid(format!("`selector`: {error}")))?,
            resource_types: if create.resource_types.is_empty() {
                vec![permguard_core::authz::resource_types::ANY.to_owned()]
            } else {
                create.resource_types.clone()
            },
            constraints: create.constraints.clone(),
            issued_by: admitted.principal.as_str().to_owned(),
            expires_at: match &create.expires_at {
                Some(text) => Some(parse_instant(text, "expires_at")?),
                None => None,
            },
        };
        // What the store would never write is refused before the operation begins (step 1).
        let checked = issue.clone();
        self.transact(
            &admitted.principal,
            CREATE,
            AUDIT_ISSUED,
            &mutation,
            &create,
            None,
            || crate::authz::validate_issue(&checked, now).map_err(refusal_of),
            |applying| {
                let record = store
                    .issue(applying, issue, now, mutation.expected_revision)
                    .map_err(|error| failure(error, refusal_of))?;
                Ok(Applied {
                    revision: record.revision,
                    target: Some(record.grant_id.to_string()),
                    value: Created {
                        receipt: self.receipt(applying.operation_id(), record.revision),
                        grant: record.into(),
                    },
                })
            },
            |operation_id, revision, target| {
                let record = grant_of(store, reconciled_grant(target.as_deref())?)?;
                Ok(Created {
                    receipt: self.receipt(operation_id, revision),
                    grant: record.into(),
                })
            },
        )
    }

    /// `POST /host/v1/grants/{id}/revoke/plan`.
    pub async fn plan_revoke(
        &self,
        actor: &Actor,
        grant_id: &str,
        plan: PlanRevoke,
    ) -> Result<Planned, Refusal> {
        let admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let store = self.store()?;
        let id = parse_grant_id(grant_id)?;
        let mutation = Mutation {
            request_id: plan.request_id.clone(),
            expected_revision: plan.expected_revision,
        };
        let now = self.time.now_secs();
        let target = (grant_id, &plan);
        // Read before the operation begins (step 1): a grant unknown, terminal or changed since
        // the caller read it is refused without an intent.
        let current = || -> Result<GrantRecord, Refusal> {
            let record = grant_of(store, id)?;
            if record.status != Status::Active {
                return Err(terminal(&record));
            }
            if let Some(expected) = mutation.expected_revision
                && expected != record.revision
            {
                return Err(Refusal::revision_mismatch(expected, record.revision));
            }
            Ok(record)
        };
        self.transact(
            &admitted.principal,
            REVOKE_PLAN,
            AUDIT_REVOKE_PLANNED,
            &mutation,
            &target,
            Some(id.to_string()),
            || current().map(|_| ()),
            |applying| {
                let record = current().map_err(Failure::Refused)?;
                let expires = now.saturating_add(PLAN_LIFETIME.as_secs());
                let plan_id = mint_id().map_err(Failure::Refused)?;
                let digest = plan_digest(
                    &plan_id,
                    REVOKE,
                    &record.grant_id.to_string(),
                    record.revision,
                    admitted.principal.as_str(),
                    expires,
                );
                self.replay
                    .plan(
                        applying,
                        Plan {
                            plan_id: plan_id.clone(),
                            operation: REVOKE.to_owned(),
                            target: record.grant_id.to_string(),
                            revision: record.revision,
                            digest: digest.clone(),
                            expires,
                            principal: admitted.principal.as_str().to_owned(),
                        },
                    )
                    .map_err(Failure::Refused)?;
                Ok(Applied {
                    revision: record.revision,
                    target: Some(record.grant_id.to_string()),
                    value: Planned {
                        plan_id,
                        plan_digest: digest,
                        expires: rfc3339(expires),
                        revision: record.revision,
                    },
                })
            },
            // A plan leaves no trace in the grant store, so recovery never commits one: it is
            // marked failed, and the plan, which nobody was answered, expires unused.
            |_, _, _| Err(unreachable_reconciliation(REVOKE_PLAN)),
        )
    }

    /// `POST /host/v1/grants/{id}/revoke/run`.
    pub async fn run_revoke(
        &self,
        actor: &Actor,
        grant_id: &str,
        run: RunRevoke,
    ) -> Result<Revoked, Refusal> {
        let admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let store = self.store()?;
        let id = parse_grant_id(grant_id)?;
        let mutation = Mutation {
            request_id: run.request_id.clone(),
            expected_revision: None,
        };
        let now = self.time.now_secs();
        let target = (grant_id, &run);
        // The plan is read and checked before the operation begins (step 1).
        let presented = || -> Result<Plan, Refusal> {
            let plan = self
                .replay
                .plan_of(&admitted.principal, &run.plan_id, now)?;
            if plan.operation != REVOKE || plan.target != id.to_string() {
                return Err(Refusal::new(
                    ErrorClass::NotFound,
                    codes::host::PLAN_UNKNOWN,
                    "no plan of that id is held for this grant",
                ));
            }
            if plan.digest != run.plan_digest {
                return Err(Refusal::new(
                    ErrorClass::Validation,
                    codes::host::PLAN_DIGEST_MISMATCH,
                    "the plan digest presented is not the one the plan step answered",
                ));
            }
            Ok(plan)
        };
        self.transact(
            &admitted.principal,
            REVOKE_RUN,
            AUDIT_REVOKED,
            &mutation,
            &target,
            Some(id.to_string()),
            || presented().map(|_| ()),
            |applying| {
                let plan = presented().map_err(Failure::Refused)?;
                // The grant's revision is compared under the journal lock: a grant changed since
                // the plan is refused with its current revision.
                let revoked = store
                    .revoke(
                        applying,
                        id,
                        admitted.principal.as_str(),
                        now,
                        Some(plan.revision),
                    )
                    .map_err(|error| failure(error, refusal_of))?;
                // The grant is terminal now, so a plan left unconsumed can never run again; its
                // marker only spares the caller a `grant_terminal` for `plan_expired`.
                if let Err(error) = self
                    .replay
                    .consume(applying, &admitted.principal, &run.plan_id)
                {
                    tracing::warn!(
                        event.name = "host.plan_unconsumed",
                        component = super::COMPONENT,
                        error = %error,
                        "a run plan could not be marked consumed; its grant is revoked"
                    );
                }
                Ok(Applied {
                    revision: revoked.revision,
                    target: Some(revoked.grant_id.to_string()),
                    value: Revoked {
                        receipt: self.receipt(applying.operation_id(), revoked.revision),
                        grant: revoked.into(),
                    },
                })
            },
            |operation_id, revision, _| {
                let record = grant_of(store, id)?;
                Ok(Revoked {
                    receipt: self.receipt(operation_id, revision),
                    grant: record.into(),
                })
            },
        )
    }
}

/// The grant a reconciled create names.
fn reconciled_grant(target: Option<&str>) -> Result<GrantId, Refusal> {
    target
        .and_then(|text| GrantId::parse(text).ok())
        .ok_or_else(|| unreachable_reconciliation(CREATE))
}

/// The refusal of a reconciled operation whose answer cannot be rebuilt: said as applied, so the
/// caller reads before it retries.
fn unreachable_reconciliation(operation: &str) -> Refusal {
    Refusal::new(
        ErrorClass::Internal,
        codes::host::MUTATION_UNRECORDED,
        format!(
            "`{operation}` was applied before a restart and its answer cannot be rebuilt: read \
             the current state before retrying"
        ),
    )
}

/// The most members a grant's lists may carry: a bound checked before the journal is asked, so
/// an oversized grant is a validation refusal, never a storage one.
pub const MAX_OPERATIONS: usize = 64;
/// The most resource types a grant may name.
pub const MAX_RESOURCE_TYPES: usize = 16;
/// The most constraints a grant may carry.
pub const MAX_CONSTRAINTS: usize = 32;
/// The longest constraint key or value, in bytes.
pub const MAX_CONSTRAINT_BYTES: usize = 256;

/// Refuses a create whose lists are over their bounds.
fn bounded(create: &CreateGrant) -> Result<(), Refusal> {
    if create.operations.len() > MAX_OPERATIONS {
        return Err(invalid(format!(
            "`operations` names {} operations; at most {MAX_OPERATIONS}",
            create.operations.len()
        )));
    }
    if create.resource_types.len() > MAX_RESOURCE_TYPES {
        return Err(invalid(format!(
            "`resource_types` names {} types; at most {MAX_RESOURCE_TYPES}",
            create.resource_types.len()
        )));
    }
    if create.constraints.len() > MAX_CONSTRAINTS {
        return Err(invalid(format!(
            "`constraints` carries {} entries; at most {MAX_CONSTRAINTS}",
            create.constraints.len()
        )));
    }
    if create
        .constraints
        .iter()
        .any(|(key, value)| key.len() > MAX_CONSTRAINT_BYTES || value.len() > MAX_CONSTRAINT_BYTES)
    {
        return Err(invalid(format!(
            "a constraint key or value is longer than {MAX_CONSTRAINT_BYTES} bytes"
        )));
    }
    Ok(())
}

/// The digest of a plan: what the run step must present back.
fn plan_digest(
    plan_id: &str,
    operation: &str,
    target: &str,
    revision: u64,
    principal: &str,
    expires: u64,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        plan_id,
        operation,
        target,
        &revision.to_string(),
        principal,
        &expires.to_string(),
    ] {
        hasher.update(part.len().to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let mut text = String::with_capacity(64);
    for byte in hasher.finalize() {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn grant_of(store: &crate::authz::GrantStore, id: GrantId) -> Result<GrantRecord, Refusal> {
    store
        .records()
        .into_iter()
        .find(|record| record.grant_id == id)
        .ok_or_else(|| {
            Refusal::new(
                ErrorClass::NotFound,
                codes::host::GRANT_UNKNOWN,
                format!("no grant `{id}` is held"),
            )
        })
}

fn terminal(record: &GrantRecord) -> Refusal {
    Refusal::new(
        ErrorClass::Conflict,
        codes::host::GRANT_TERMINAL,
        format!(
            "grant `{}` is {}, which is terminal",
            record.grant_id,
            record.status.as_str()
        ),
    )
}

fn parse_grant_id(text: &str) -> Result<GrantId, Refusal> {
    GrantId::parse(text).map_err(|error| invalid(format!("the grant id: {error}")))
}

fn parse_instant(text: &str, member: &str) -> Result<u64, Refusal> {
    permguard_core::time::from_rfc3339(text)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or_else(|| invalid(format!("`{member}` is not an RFC 3339 instant")))
}

fn invalid(message: String) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        message,
    )
}

fn refusal_of(error: AuthzError) -> Refusal {
    match error {
        AuthzError::Invalid(detail) => invalid(detail),
        AuthzError::Unknown(id) => Refusal::new(
            ErrorClass::NotFound,
            codes::host::GRANT_UNKNOWN,
            format!("no grant `{id}` is held"),
        ),
        AuthzError::Terminal(id, status) => Refusal::new(
            ErrorClass::Conflict,
            codes::host::GRANT_TERMINAL,
            format!("grant `{id}` is {}, which is terminal", status.as_str()),
        ),
        AuthzError::Conflict { expected, current } => Refusal::revision_mismatch(expected, current),
        other @ (AuthzError::Storage(_) | AuthzError::Record(_)) => Refusal::Api(
            permguard_core::ApiError::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "the grant store could not apply the mutation",
            )
            .with_internal(other.to_string()),
        ),
    }
}

fn rfc3339(seconds: u64) -> String {
    permguard_core::time::to_rfc3339(i64::try_from(seconds).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::api::testing::{
        ADMIN, Recording, actor, admin, facade, reopen, reopen_with, scratch,
    };

    fn create(request_id: &str, principal: &str) -> CreateGrant {
        CreateGrant {
            request_id: request_id.to_owned(),
            expected_revision: None,
            principal: principal.to_owned(),
            operations: vec![operations::CATALOG_READ.to_owned()],
            selector: "plane/control/*".to_owned(),
            resource_types: Vec::new(),
            constraints: BTreeMap::new(),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn a_grant_is_listed_created_and_the_create_is_replayed_not_repeated() {
        let api = facade("grants-create");
        let before = api.grants(&admin(), None, None).expect("listed");
        assert_eq!(before.grants.len(), 1, "the test administrator");
        let created = api
            .create_grant(&admin(), create("r1", "spiffe://acme/alice"))
            .await
            .expect("created");
        assert_eq!(created.receipt.revision, before.revision + 1);
        assert_eq!(created.receipt.audit.trail, "audit");
        assert!(created.receipt.audit.seq.is_none() && created.receipt.audit.digest.is_none());
        assert_eq!(created.grant.issued_by, ADMIN);
        assert_eq!(created.grant.resource_types, vec!["*".to_owned()]);
        // The same request again: the stored answer, operation id included, and no second grant.
        let again = api
            .create_grant(&admin(), create("r1", "spiffe://acme/alice"))
            .await
            .expect("replayed");
        assert_eq!(again, created);
        let after = api
            .grants(&admin(), Some("spiffe://acme/alice"), None)
            .expect("listed");
        assert_eq!(after.grants.len(), 1);
        assert_eq!(after.revision, created.receipt.revision);
        // The same request id with another body is refused.
        let reused = api
            .create_grant(&admin(), create("r1", "spiffe://acme/bob"))
            .await
            .expect_err("reused");
        assert_eq!(
            reused.error().expect("refusal").code(),
            codes::host::REQUEST_ID_REUSED
        );
        // A filter by selector.
        let by_selector = api
            .grants(&admin(), None, Some("plane/control/*"))
            .expect("listed");
        assert_eq!(by_selector.grants.len(), 1);
    }

    #[tokio::test]
    async fn a_create_states_the_revision_it_expects_and_loses_the_race_honestly() {
        let api = facade("grants-cas");
        let current = api.grants(&admin(), None, None).expect("listed").revision;
        let mut stale = create("r1", "spiffe://acme/alice");
        stale.expected_revision = Some(current + 7);
        let refused = api.create_grant(&admin(), stale).await.expect_err("stale");
        match refused {
            Refusal::Conflict { error, revision } => {
                assert_eq!(error.code(), codes::host::REVISION_MISMATCH);
                assert_eq!(revision, current);
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        let mut fresh = create("r2", "spiffe://acme/alice");
        fresh.expected_revision = Some(current);
        assert!(api.create_grant(&admin(), fresh).await.is_ok());
    }

    #[tokio::test]
    async fn a_create_validates_before_it_journals() {
        let api = facade("grants-validate");
        let mut bad = create("r1", "spiffe://acme/alice");
        bad.operations = vec!["nope.read".to_owned()];
        let refused = api
            .create_grant(&admin(), bad)
            .await
            .expect_err("unregistered");
        assert_eq!(
            refused.error().expect("refusal").code(),
            codes::common::INVALID_ARGUMENT
        );
        let mut anonymous = create("r2", "anonymous");
        anonymous.operations = vec![operations::CATALOG_READ.to_owned()];
        assert!(api.create_grant(&admin(), anonymous).await.is_err());
        let mut when = create("r3", "spiffe://acme/alice");
        when.expires_at = Some("yesterday".to_owned());
        assert!(api.create_grant(&admin(), when).await.is_err());
        let mut no_id = create("", "spiffe://acme/alice");
        no_id.request_id = String::new();
        let refused = api
            .create_grant(&admin(), no_id)
            .await
            .expect_err("no request id");
        assert_eq!(
            refused.error().expect("refusal").code(),
            codes::host::REQUEST_ID_REQUIRED
        );
        // Nothing was journaled by the refusals.
        assert_eq!(api.grants(&admin(), None, None).expect("l").grants.len(), 1);
        // And a stranger is refused before anything is read.
        assert!(matches!(
            api.grants(&actor("spiffe://acme/stranger"), None, None),
            Err(Refusal::Denied(_))
        ));
    }

    #[tokio::test]
    async fn a_revocation_is_planned_then_run_once_with_the_plan_it_was_given() {
        let api = facade("grants-revoke");
        let created = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("created");
        let grant_id = created.grant.grant_id.clone();
        let planned = api
            .plan_revoke(
                &admin(),
                &grant_id,
                PlanRevoke {
                    request_id: "p1".to_owned(),
                    expected_revision: Some(created.grant.revision),
                },
            )
            .await
            .expect("planned");
        assert_eq!(planned.revision, created.grant.revision);
        // A wrong digest is refused and burns nothing.
        let wrong = api
            .run_revoke(
                &admin(),
                &grant_id,
                RunRevoke {
                    request_id: "x1".to_owned(),
                    plan_id: planned.plan_id.clone(),
                    plan_digest: "00".repeat(32),
                },
            )
            .await
            .expect_err("wrong digest");
        assert_eq!(
            wrong.error().expect("refusal").code(),
            codes::host::PLAN_DIGEST_MISMATCH
        );
        // Another grant's id with this plan is not this plan.
        let other = api
            .create_grant(&admin(), create("c2", "spiffe://acme/bob"))
            .await
            .expect("created");
        let misdirected = api
            .run_revoke(
                &admin(),
                &other.grant.grant_id,
                RunRevoke {
                    request_id: "x2".to_owned(),
                    plan_id: planned.plan_id.clone(),
                    plan_digest: planned.plan_digest.clone(),
                },
            )
            .await
            .expect_err("another target");
        assert_eq!(
            misdirected.error().expect("refusal").code(),
            codes::host::PLAN_UNKNOWN
        );
        let run = RunRevoke {
            request_id: "r1".to_owned(),
            plan_id: planned.plan_id.clone(),
            plan_digest: planned.plan_digest.clone(),
        };
        let revoked = api
            .run_revoke(&admin(), &grant_id, run.clone())
            .await
            .expect("revoked");
        assert_eq!(revoked.grant.status, "revoked");
        assert!(revoked.receipt.revision > created.receipt.revision);
        // The same request id replays the stored answer.
        let again = api
            .run_revoke(&admin(), &grant_id, run)
            .await
            .expect("replayed");
        assert_eq!(again, revoked);
        // A new request with the consumed plan is refused: the grant is terminal anyway.
        let consumed = api
            .run_revoke(
                &admin(),
                &grant_id,
                RunRevoke {
                    request_id: "r2".to_owned(),
                    plan_id: planned.plan_id.clone(),
                    plan_digest: planned.plan_digest.clone(),
                },
            )
            .await
            .expect_err("consumed");
        assert_eq!(
            consumed.error().expect("refusal").code(),
            codes::host::PLAN_EXPIRED
        );
        // Planning against a revoked grant is a conflict.
        let terminal = api
            .plan_revoke(
                &admin(),
                &grant_id,
                PlanRevoke {
                    request_id: "p2".to_owned(),
                    expected_revision: None,
                },
            )
            .await
            .expect_err("terminal");
        assert_eq!(
            terminal.error().expect("refusal").code(),
            codes::host::GRANT_TERMINAL
        );
        let unknown = api
            .plan_revoke(
                &admin(),
                &"0".repeat(32),
                PlanRevoke {
                    request_id: "p3".to_owned(),
                    expected_revision: None,
                },
            )
            .await
            .expect_err("unknown");
        assert_eq!(
            unknown.error().expect("refusal").code(),
            codes::host::GRANT_UNKNOWN
        );
        let malformed = api
            .plan_revoke(
                &admin(),
                "not-an-id",
                PlanRevoke {
                    request_id: "p4".to_owned(),
                    expected_revision: None,
                },
            )
            .await
            .expect_err("malformed");
        assert_eq!(
            malformed.error().expect("refusal").code(),
            codes::common::INVALID_ARGUMENT
        );
    }

    #[tokio::test]
    async fn a_plan_made_against_a_stale_revision_is_refused_with_the_current_one() {
        let api = facade("grants-plan-cas");
        let created = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("created");
        let refused = api
            .plan_revoke(
                &admin(),
                &created.grant.grant_id,
                PlanRevoke {
                    request_id: "p1".to_owned(),
                    expected_revision: Some(created.grant.revision + 1),
                },
            )
            .await
            .expect_err("stale");
        assert!(matches!(
            refused,
            Refusal::Conflict { revision, .. } if revision == created.grant.revision
        ));
    }

    #[tokio::test]
    async fn the_replayed_answer_survives_a_restart() {
        let root = scratch("grants-restart");
        let created = {
            let (api, _, _volume) = reopen(&root, Vec::new());
            api.create_grant(&admin(), create("r1", "spiffe://acme/alice"))
                .await
                .expect("created")
        };
        let (api, _, _volume) = reopen(&root, Vec::new());
        let again = api
            .create_grant(&admin(), create("r1", "spiffe://acme/alice"))
            .await
            .expect("replayed across the restart");
        assert_eq!(again, created);
        assert_eq!(
            api.grants(&admin(), Some("spiffe://acme/alice"), None)
                .expect("listed")
                .grants
                .len(),
            1
        );
    }

    fn facade_auditing(tag: &str) -> (HostApi, std::sync::Arc<Recording>, std::path::PathBuf) {
        let trail = std::sync::Arc::new(Recording::default());
        let root = scratch(tag);
        let (api, _, volume) = reopen_with(&root, Vec::new(), std::sync::Arc::clone(&trail));
        std::mem::forget(volume);
        (api, trail, root)
    }

    /// The records of the administrator's operations, the test's own seed left out.
    fn administrator_records(trail: &Recording) -> Vec<crate::api::testing::Recorded> {
        trail
            .events
            .lock()
            .expect("lock")
            .iter()
            .filter(|(_, subject, ..)| *subject == format!("principal:{ADMIN}"))
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn every_mutation_records_its_intent_and_its_outcome_with_principal_and_target() {
        let (api, trail, _) = facade_auditing("grants-audit");
        let created = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("created");
        let grant_id = created.grant.grant_id.clone();
        // A replayed create records nothing twice.
        api.create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("replayed");
        let planned = api
            .plan_revoke(
                &admin(),
                &grant_id,
                PlanRevoke {
                    request_id: "p1".to_owned(),
                    expected_revision: None,
                },
            )
            .await
            .expect("planned");
        api.run_revoke(
            &admin(),
            &grant_id,
            RunRevoke {
                request_id: "r1".to_owned(),
                plan_id: planned.plan_id,
                plan_digest: planned.plan_digest,
            },
        )
        .await
        .expect("revoked");
        let principal = format!("principal:{ADMIN}");
        let record = |action: &str, target: Option<&String>, phase: &'static str| {
            (
                action.to_owned(),
                principal.clone(),
                target.cloned(),
                Some(phase),
            )
        };
        assert_eq!(
            administrator_records(&trail),
            vec![
                record(AUDIT_ISSUED, None, "intent"),
                record(AUDIT_ISSUED, Some(&grant_id), "applied"),
                record(AUDIT_REVOKE_PLANNED, Some(&grant_id), "intent"),
                record(AUDIT_REVOKE_PLANNED, Some(&grant_id), "applied"),
                record(AUDIT_REVOKED, Some(&grant_id), "intent"),
                record(AUDIT_REVOKED, Some(&grant_id), "applied"),
            ]
        );
    }

    #[tokio::test]
    async fn an_audit_intent_that_fails_applies_nothing_and_a_retry_applies_once_it_is_back() {
        let (api, trail, _) = facade_auditing("grants-audit-intent");
        trail
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let refused = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect_err("the trail refused");
        let error = refused.error().expect("a domain refusal");
        assert_eq!(error.code(), codes::host::AUDIT_UNAVAILABLE);
        assert_eq!(error.http_status(), 503);
        assert!(
            api.grants(&admin(), Some("spiffe://acme/alice"), None)
                .expect("listed")
                .grants
                .is_empty(),
            "nothing applied"
        );
        // Still down: every security mutation is refused, the failure record still pending.
        let refused = api
            .create_grant(&admin(), create("c2", "spiffe://acme/bob"))
            .await
            .expect_err("still refused");
        assert_eq!(
            refused.error().expect("refusal").code(),
            codes::host::AUDIT_UNAVAILABLE
        );
        trail
            .refuse
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let created = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("applied now, under a new operation");
        let records = administrator_records(&trail);
        assert_eq!(
            records.first().map(|record| record.3),
            Some(Some("failed")),
            "the failed attempt's outcome is recorded first: {records:?}"
        );
        assert_eq!(
            api.grants(&admin(), Some("spiffe://acme/alice"), None)
                .expect("listed")
                .grants
                .len(),
            1
        );
        assert_eq!(created.grant.principal, "spiffe://acme/alice");
    }

    #[tokio::test]
    async fn an_outcome_record_that_fails_is_unrecorded_the_mutation_stands_and_is_replayed_once_written()
     {
        let (api, trail, _) = facade_auditing("grants-audit-outcome");
        *trail.refuse_phase.lock().expect("lock") = Some("applied");
        let refused = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect_err("the outcome record failed");
        let error = refused.error().expect("a domain refusal");
        assert_eq!(error.code(), codes::host::MUTATION_UNRECORDED);
        assert_eq!(error.http_status(), 500);
        let listed = api
            .grants(&admin(), Some("spiffe://acme/alice"), None)
            .expect("listed");
        assert_eq!(listed.grants.len(), 1, "never rolled back");
        // While the record waits, a retry is not answered success and a new mutation is refused.
        let retried = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect_err("not a success yet");
        assert_eq!(
            retried.error().expect("refusal").code(),
            codes::host::MUTATION_UNRECORDED
        );
        let refused = api
            .create_grant(&admin(), create("c2", "spiffe://acme/bob"))
            .await
            .expect_err("refused while a record waits");
        assert_eq!(
            refused.error().expect("refusal").code(),
            codes::host::AUDIT_UNAVAILABLE
        );
        *trail.refuse_phase.lock().expect("lock") = None;
        let replayed = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("the committed answer, its record now written");
        assert_eq!(replayed.grant.grant_id, listed.grants[0].grant_id);
        let applied: Vec<_> = administrator_records(&trail)
            .into_iter()
            .filter(|record| record.3 == Some("applied"))
            .collect();
        assert_eq!(applied.len(), 1, "written once");
    }

    #[tokio::test]
    async fn a_commit_that_fails_is_unrecorded_and_a_restart_reconciles_what_the_store_shows() {
        use permguard_core::fault::{Fault, inject};

        let trail = std::sync::Arc::new(Recording::default());
        let root = scratch("grants-commit-fails");
        let journal = {
            let (api, _, volume) = reopen_with(&root, Vec::new(), std::sync::Arc::clone(&trail));
            let journal = volume
                .host()
                .path()
                .join(crate::audit::DIRECTORY)
                .join(crate::operations::mutation::DIRECTORY);
            // The intent is written; from its audit record on, the journal refuses every write.
            let armed = std::sync::Arc::new(std::sync::Mutex::new(None));
            let holder = std::sync::Arc::clone(&armed);
            let path = journal.clone();
            *trail.on_intent.lock().expect("lock") = Some(Box::new(move || {
                *holder.lock().expect("lock") = Some(inject(&path, Fault::WriteFails));
            }));
            let refused = api
                .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
                .await
                .expect_err("the commit could not be written");
            assert_eq!(
                refused.error().expect("refusal").code(),
                codes::host::MUTATION_UNRECORDED
            );
            drop(armed.lock().expect("lock").take());
            journal
        };
        assert!(journal.is_dir());
        // A restart: the intent is open, the store shows its operation, recovery commits it.
        let (api, store, _volume) = reopen_with(&root, Vec::new(), std::sync::Arc::clone(&trail));
        let alice: Vec<_> = store
            .records()
            .into_iter()
            .filter(|record| record.principal_id.as_str() == "spiffe://acme/alice")
            .collect();
        assert_eq!(alice.len(), 1);
        let replayed = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("the retry learns the durable result");
        assert_eq!(replayed.grant.grant_id, alice[0].grant_id.to_string());
        assert_eq!(
            replayed.receipt.operation_id,
            alice[0]
                .operation_id
                .expect("issued by an operation")
                .to_string()
        );
        assert!(
            administrator_records(&trail)
                .iter()
                .any(|record| record.3 == Some("reconciled")),
            "recovery records the reconciliation"
        );
    }

    #[tokio::test]
    async fn a_request_the_store_would_refuse_leaves_no_intent_and_no_record() {
        let (api, trail, _) = facade_auditing("grants-validate-first");
        let mut bad = create("v1", "spiffe://acme/alice");
        bad.operations = vec!["nope.read".to_owned()];
        api.create_grant(&admin(), bad)
            .await
            .expect_err("unregistered");
        let created = api
            .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
            .await
            .expect("created");
        let stale = api
            .plan_revoke(
                &admin(),
                &created.grant.grant_id,
                PlanRevoke {
                    request_id: "p1".to_owned(),
                    expected_revision: Some(created.grant.revision + 9),
                },
            )
            .await
            .expect_err("stale");
        assert!(matches!(stale, Refusal::Conflict { .. }));
        let phases: Vec<_> = administrator_records(&trail)
            .into_iter()
            .map(|record| record.3)
            .collect();
        assert_eq!(
            phases,
            vec![Some("intent"), Some("applied")],
            "only the create that applied is on the trail"
        );
    }

    #[tokio::test]
    async fn an_answer_the_replay_journal_recorded_before_wp_3_6_still_answers() {
        let api = facade("grants-legacy");
        let request = create("legacy", "spiffe://acme/alice");
        let principal = Principal::new(ADMIN).expect("a principal");
        let stored = Created {
            receipt: Receipt {
                operation_id: "ab".repeat(16),
                revision: 7,
                audit: crate::api::AuditReference {
                    trail: "audit".to_owned(),
                    seq: None,
                    digest: None,
                },
            },
            grant: api
                .grants(&admin(), None, None)
                .expect("listed")
                .grants
                .remove(0),
        };
        api.replay
            .record(
                &principal,
                "legacy",
                CREATE,
                &crate::api::replay::digest_of(&request).expect("a digest"),
                &stored,
            )
            .expect("recorded");
        let answered = api
            .create_grant(&admin(), request)
            .await
            .expect("the stored answer");
        assert_eq!(answered, stored);
        assert!(
            api.grants(&admin(), Some("spiffe://acme/alice"), None)
                .expect("listed")
                .grants
                .is_empty(),
            "nothing applied again"
        );
    }

    #[tokio::test]
    async fn a_revocation_whose_commit_failed_is_rebuilt_from_the_store_after_a_restart() {
        use permguard_core::fault::{Fault, inject};

        let trail = std::sync::Arc::new(Recording::default());
        let root = scratch("grants-run-reconciled");
        let run = {
            let (api, _, volume) = reopen_with(&root, Vec::new(), std::sync::Arc::clone(&trail));
            let journal = volume
                .host()
                .path()
                .join(crate::audit::DIRECTORY)
                .join(crate::operations::mutation::DIRECTORY);
            let created = api
                .create_grant(&admin(), create("c1", "spiffe://acme/alice"))
                .await
                .expect("created");
            let planned = api
                .plan_revoke(
                    &admin(),
                    &created.grant.grant_id,
                    PlanRevoke {
                        request_id: "p1".to_owned(),
                        expected_revision: None,
                    },
                )
                .await
                .expect("planned");
            let run = RunRevoke {
                request_id: "r1".to_owned(),
                plan_id: planned.plan_id,
                plan_digest: planned.plan_digest,
            };
            let armed = std::sync::Arc::new(std::sync::Mutex::new(None));
            let holder = std::sync::Arc::clone(&armed);
            *trail.on_intent.lock().expect("lock") = Some(Box::new(move || {
                *holder.lock().expect("lock") = Some(inject(&journal, Fault::WriteFails));
            }));
            let refused = api
                .run_revoke(&admin(), &created.grant.grant_id, run.clone())
                .await
                .expect_err("the commit could not be written");
            assert_eq!(
                refused.error().expect("refusal").code(),
                codes::host::MUTATION_UNRECORDED
            );
            drop(armed.lock().expect("lock").take());
            (created.grant.grant_id, run)
        };
        let (grant_id, run) = run;
        let (api, store, _volume) = reopen_with(&root, Vec::new(), std::sync::Arc::clone(&trail));
        let revoked = api
            .run_revoke(&admin(), &grant_id, run)
            .await
            .expect("the retry learns the revocation");
        assert_eq!(revoked.grant.status, "revoked");
        let record = store
            .records()
            .into_iter()
            .find(|record| record.grant_id.to_string() == grant_id)
            .expect("the grant");
        assert_eq!(revoked.receipt.revision, record.revision);
    }

    #[tokio::test]
    async fn a_create_over_its_list_bounds_is_a_validation_refusal() {
        let api = facade("grants-bounds");
        let mut wide = create("b1", "spiffe://acme/alice");
        wide.operations = (0..=MAX_OPERATIONS)
            .map(|_| operations::CATALOG_READ.to_owned())
            .collect();
        let refused = api
            .create_grant(&admin(), wide)
            .await
            .expect_err("too many operations");
        assert_eq!(
            refused.error().expect("refusal").code(),
            codes::common::INVALID_ARGUMENT
        );
        let mut typed = create("b4", "spiffe://acme/alice");
        typed.resource_types = (0..=MAX_RESOURCE_TYPES).map(|_| "*".to_owned()).collect();
        assert!(api.create_grant(&admin(), typed).await.is_err());
        let mut heavy = create("b2", "spiffe://acme/alice");
        heavy.constraints = (0..=MAX_CONSTRAINTS)
            .map(|index| (format!("k{index}"), "v".to_owned()))
            .collect();
        assert!(api.create_grant(&admin(), heavy).await.is_err());
        let mut long = create("b3", "spiffe://acme/alice");
        long.constraints = BTreeMap::from([("k".to_owned(), "v".repeat(MAX_CONSTRAINT_BYTES + 1))]);
        assert!(api.create_grant(&admin(), long).await.is_err());
        assert_eq!(api.grants(&admin(), None, None).expect("l").grants.len(), 1);
    }

    #[test]
    fn the_plan_digest_binds_every_part() {
        let base = plan_digest("p", REVOKE, "g", 1, "alice", 10);
        assert_ne!(base, plan_digest("q", REVOKE, "g", 1, "alice", 10));
        assert_ne!(base, plan_digest("p", REVOKE, "h", 1, "alice", 10));
        assert_ne!(base, plan_digest("p", REVOKE, "g", 2, "alice", 10));
        assert_ne!(base, plan_digest("p", REVOKE, "g", 1, "bob", 10));
        assert_ne!(base, plan_digest("p", REVOKE, "g", 1, "alice", 11));
        // Length-prefixed, so a boundary cannot move.
        assert_ne!(
            plan_digest("ab", "c", "g", 1, "a", 1),
            plan_digest("a", "bc", "g", 1, "a", 1)
        );
    }
}
