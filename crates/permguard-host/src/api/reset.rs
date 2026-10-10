// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The identity reset on the Host API (WP-4.1, owner decisions of 2026-10-09): two steps under
//! `identity.admin`, a destructive mutation that leaves a new `host_id` for the next start.
//!
//! | Route                                   | Answer                                                         |
//! | --------------------------------------- | -------------------------------------------------------------- |
//! | `POST /host/v1/identity/reset/plan`     | the plan: every live membership and what the reset does to it  |
//! | `POST /host/v1/identity/reset/run`      | the receipt, the revocations, `orphaned[]` and the new identity |
//!
//! The run follows the blueprint's order: each coordinator asked to revoke the memberships this
//! Host is a member of, their revoked manifests kept as receipts; a normal reset that does not
//! reach them all is refused (`identity_reset_incomplete`) and changes no identity, an emergency
//! one marks them `orphaned` and names their coordinators; the memberships this Host coordinates
//! ended here; then the identity retired, its public evidence kept and the next provisioned.
//! The process signs nothing more and serves the new identity after a restart.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, operations};
use permguard_core::{ErrorClass, codes};

use super::grants::{plan_digest, rfc3339, unreachable_reconciliation};
use super::members::{HostView, refusal_of};
use super::replay::{PLAN_LIFETIME, Plan, mint_id};
use super::{HostApi, Mutation, Receipt, Refusal};
use crate::identity::record::uuid_text;
use crate::identity::reset::{AUDIT_RESET, AUDIT_RESET_PLANNED, RESET_PLAN, RESET_RUN};
use crate::identity::{self, IdentityError};
use crate::membership::reset::{self as settle, Step};
use crate::membership::{Held, MembershipError};
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Failure};

/// The reset a plan names.
const RESET: &str = "identity.reset";

/// How a reset treats a coordinator it does not reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Refused until every coordinator acknowledged.
    Normal,
    /// The unreached memberships `orphaned`, their coordinators named.
    Emergency,
}

impl Mode {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "normal" => Some(Self::Normal),
            "emergency" => Some(Self::Emergency),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Emergency => "emergency",
        }
    }
}

/// `POST /host/v1/identity/reset/plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanIdentityReset {
    pub request_id: String,
    /// `normal` or `emergency`.
    pub mode: String,
    /// Why, printable: kept in the audit.
    pub reason: String,
}

/// One live membership, as a reset plan names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetMembership {
    pub membership_id: String,
    /// This Host's role in it.
    pub role: String,
    pub status: String,
    /// The other Host.
    pub peer: HostView,
    /// Where the coordinator is, for a membership this Host is a member of.
    pub address: Option<String>,
    /// `revoke_remote`, `revoke_local` or `reject_local`.
    pub step: String,
}

impl ResetMembership {
    fn of(id: &[u8; 16], held: &Held, step: Step) -> Self {
        let peer = match held.role {
            crate::membership::record::Role::Coordinator => &held.request.member,
            crate::membership::record::Role::Member => &held.request.coordinator,
        };
        Self {
            membership_id: uuid_text(id),
            role: held.role.as_str().to_owned(),
            status: held.status.as_str().to_owned(),
            peer: peer.into(),
            address: held.request.coordinator_address.clone(),
            step: step.as_str().to_owned(),
        }
    }
}

/// What a reset plan answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityResetPlan {
    pub plan_id: String,
    pub plan_digest: String,
    /// RFC 3339: when the plan can no longer be run.
    pub expires: String,
    /// The identity epoch the plan was made at.
    pub revision: u64,
    pub mode: String,
    pub memberships: Vec<ResetMembership>,
}

/// `POST /host/v1/identity/reset/run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIdentityReset {
    pub request_id: String,
    pub plan_id: String,
    pub plan_digest: String,
}

/// A membership the reset ended, with its last manifest: a coordinator's revocation receipt, or
/// the manifest this Host issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetEnded {
    pub membership_id: String,
    pub role: String,
    pub status: String,
    pub epoch: u64,
    /// COSE_Sign1 `permguard.membership.manifest.v1`, base64url.
    pub manifest: Option<String>,
}

impl ResetEnded {
    fn of(held: &Held) -> Self {
        Self {
            membership_id: uuid_text(&held.request.membership_id),
            role: held.role.as_str().to_owned(),
            status: held.status.as_str().to_owned(),
            epoch: held.epoch(),
            manifest: held
                .manifest
                .as_ref()
                .map(|(_, envelope, _)| URL_SAFE_NO_PAD.encode(envelope)),
        }
    }
}

/// A membership the reset left `orphaned`: its coordinator revokes it out of band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetOrphaned {
    pub membership_id: String,
    pub coordinator: HostView,
    pub address: Option<String>,
}

/// What a reset run answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityResetDone {
    pub receipt: Receipt,
    pub old_host_id: String,
    pub host_id: String,
    /// The new identity's first fingerprint: what peers pin.
    pub fingerprint: String,
    /// The new identity's external witness, for `host.identity.witness`.
    pub witness: String,
    pub ended: Vec<ResetEnded>,
    pub orphaned: Vec<ResetOrphaned>,
    /// Always true: the process serves the new identity after a restart.
    pub restart_required: bool,
}

fn invalid(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        detail,
    )
}

fn retired() -> Refusal {
    Refusal::new(
        ErrorClass::Unavailable,
        codes::host::IDENTITY_UNAVAILABLE,
        "the Host identity was reset: restart the process to serve the new one",
    )
}

fn unprovisioned() -> Refusal {
    Refusal::new(
        ErrorClass::Unavailable,
        codes::host::IDENTITY_UNAVAILABLE,
        "this process cannot provision a new identity: no provisioner is composed",
    )
}

impl HostApi {
    /// `POST /host/v1/identity/reset/plan`.
    pub async fn plan_identity_reset(
        &self,
        actor: &Actor,
        plan: PlanIdentityReset,
    ) -> Result<IdentityResetPlan, Refusal> {
        let admitted = self.admit(actor, operations::IDENTITY_ADMIN)?;
        let identity = self.host_identity()?;
        if !identity.can_reset() {
            return Err(unprovisioned());
        }
        let mode =
            Mode::parse(&plan.mode).ok_or_else(|| invalid("`mode` is `normal` or `emergency`"))?;
        if plan.reason.is_empty()
            || plan.reason.len() > 256
            || plan.reason.chars().any(char::is_control)
        {
            return Err(invalid("`reason` is printable text of 1 to 256 bytes"));
        }
        let memberships = self.memberships()?;
        let now = self.time.now_secs();
        let mutation = Mutation {
            request_id: plan.request_id.clone(),
            expected_revision: None,
        };
        let target = Some(format!("reset:{}", identity.host_id_text()));
        self.transact(
            identity::DOMAIN,
            &admitted.principal,
            RESET_PLAN,
            AUDIT_RESET_PLANNED,
            &mutation,
            &plan,
            target.clone(),
            || Ok(()),
            |applying| {
                let planned = settle::plan(&memberships.store);
                let held = format!("{}\n{}", mode.as_str(), settle::digest_target(&planned));
                let revision = identity.epoch();
                let expires = now.saturating_add(PLAN_LIFETIME.as_secs());
                let plan_id = mint_id().map_err(Failure::Refused)?;
                let digest = plan_digest(
                    &plan_id,
                    RESET,
                    &held,
                    revision,
                    admitted.principal.as_str(),
                    expires,
                );
                self.replay
                    .plan(
                        applying,
                        Plan {
                            plan_id: plan_id.clone(),
                            operation: RESET.to_owned(),
                            target: held,
                            revision,
                            digest: digest.clone(),
                            expires,
                            principal: admitted.principal.as_str().to_owned(),
                        },
                    )
                    .map_err(Failure::Refused)?;
                Ok(Applied {
                    revision,
                    target: target.clone(),
                    value: IdentityResetPlan {
                        plan_id,
                        plan_digest: digest,
                        expires: rfc3339(expires),
                        revision,
                        mode: mode.as_str().to_owned(),
                        memberships: planned
                            .iter()
                            .map(|(id, held, step)| ResetMembership::of(id, held, *step))
                            .collect(),
                    },
                })
            },
            |_, _, _| Err(unreachable_reconciliation(RESET_PLAN)),
        )
    }

    /// `POST /host/v1/identity/reset/run`.
    pub async fn run_identity_reset(
        &self,
        actor: &Actor,
        run: RunIdentityReset,
    ) -> Result<IdentityResetDone, Refusal> {
        let admitted = self.admit(actor, operations::IDENTITY_ADMIN)?;
        let mutation = Mutation {
            request_id: run.request_id.clone(),
            expected_revision: None,
        };
        mutation.validated()?;
        let identity = self.open_identity()?;
        if identity.is_retired() {
            // The run that reset it, retried, answers from the replay window; nothing else runs.
            return self.transact(
                identity::DOMAIN,
                &admitted.principal,
                RESET_RUN,
                AUDIT_RESET,
                &mutation,
                &run,
                None,
                || Err(retired()),
                |_| Err(Failure::Refused(retired())),
                |_, _, _| Err(retired()),
            );
        }
        if !identity.can_reset() {
            return Err(unprovisioned());
        }
        let memberships = self.memberships()?;
        let now = self.time.now_secs();
        let plan = self
            .replay
            .plan_of(&admitted.principal, &run.plan_id, now)?;
        if plan.operation != RESET {
            return Err(Refusal::new(
                ErrorClass::NotFound,
                codes::host::PLAN_UNKNOWN,
                "no reset plan of that id is held",
            ));
        }
        if plan.digest != run.plan_digest {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::host::PLAN_DIGEST_MISMATCH,
                "the plan digest presented is not the one the plan step answered",
            ));
        }
        let (mode, bound) = plan
            .target
            .split_once('\n')
            .and_then(|(mode, bound)| Some((Mode::parse(mode)?, bound)))
            .ok_or_else(|| unreachable_reconciliation(RESET_RUN))?;
        let planned = settle::plan(&memberships.store);
        if plan.revision != identity.epoch() || settle::digest_target(&planned) != bound {
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::REVISION_MISMATCH,
                "the identity or its memberships changed since the plan: plan again",
            ));
        }
        let initiator = Initiator::Principal(admitted.principal.as_str().to_owned());
        // Nothing irreversible before every local step is known to be possible.
        let coordinator = self.coordinator()?;
        settle::preflight(&memberships.store, &coordinator, now).map_err(refusal_of)?;

        // Each coordinator asked to revoke; its revoked manifest is the receipt.
        let mut ended = Vec::new();
        let mut unreached = Vec::new();
        for (id, held, step) in &planned {
            if *step != Step::RevokeRemote {
                continue;
            }
            let answered = match memberships.connector.as_deref() {
                Some(connector) => {
                    self.acting_member(memberships, connector)?
                        .revoke(initiator.clone(), id)
                        .await
                }
                None => Err(MembershipError::Remote {
                    code: codes::host::PEER_CLIENT_UNCONFIGURED.to_owned(),
                    reason: "this Host has no peer client".to_owned(),
                }),
            };
            match answered {
                Ok(revoked) => ended.push(ResetEnded::of(&revoked)),
                Err(error) => {
                    tracing::warn!(
                        event.name = "host.identity_reset_unacknowledged",
                        component = super::COMPONENT,
                        membership_id = %uuid_text(id),
                        error = %error,
                        "a coordinator did not acknowledge the revocation a reset asked for"
                    );
                    unreached.push((*id, held.clone()));
                }
            }
        }
        if !unreached.is_empty() && mode == Mode::Normal {
            let named: Vec<String> = unreached
                .iter()
                .map(|(id, held)| {
                    format!(
                        "{} (membership {}, {})",
                        uuid_text(&held.request.coordinator.host_id),
                        uuid_text(id),
                        held.request
                            .coordinator_address
                            .as_deref()
                            .unwrap_or("no address")
                    )
                })
                .collect();
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::IDENTITY_RESET_INCOMPLETE,
                format!(
                    "these coordinators did not acknowledge the revocation, and the identity is \
                     unchanged: {}; plan again once they answer, or plan an emergency reset",
                    named.join("; ")
                ),
            ));
        }
        let mutations = self.mutations()?;
        // From here nothing new is taken under this identity; what was offered goes first.
        memberships.store.fence();
        settle::revoke_invites(&memberships.store, mutations, &initiator, now)
            .map_err(refusal_of)?;
        for held in
            settle::end_coordinated(&memberships.store, mutations, &coordinator, &initiator, now)
                .map_err(refusal_of)?
        {
            ended.push(ResetEnded::of(&held));
        }
        let ids: Vec<[u8; 16]> = unreached.iter().map(|(id, _)| *id).collect();
        let orphaned = settle::orphan(&memberships.store, mutations, &ids, &initiator, now)
            .map_err(refusal_of)?;
        let orphaned: Vec<ResetOrphaned> = orphaned
            .iter()
            .map(|held| ResetOrphaned {
                membership_id: uuid_text(&held.request.membership_id),
                coordinator: (&held.request.coordinator).into(),
                address: held.request.coordinator_address.clone(),
            })
            .collect();

        // The identity itself, last: retired here, its evidence kept, the next provisioned.
        let old = identity.host_id_text();
        let suite = identity.suite();
        let done = self.transact(
            identity::DOMAIN,
            &admitted.principal,
            RESET_RUN,
            AUDIT_RESET,
            &mutation,
            &run,
            Some(format!("reset:{old}")),
            || Ok(()),
            |applying| {
                let reset = identity
                    .reset(
                        applying,
                        self.keys.rings(),
                        suite,
                        now,
                        now.saturating_mul(1000),
                    )
                    .map_err(|error| match error {
                        IdentityError::Refused(_) => Failure::Refused(unprovisioned()),
                        IdentityError::Retired => Failure::Refused(retired()),
                        other => Failure::Indeterminate(Refusal::Api(
                            permguard_core::ApiError::new(
                                ErrorClass::Internal,
                                codes::host::MUTATION_UNRECORDED,
                                "the reset did not complete: run it again",
                            )
                            .with_internal(other.to_string()),
                        )),
                    })?;
                if let Err(error) = self
                    .replay
                    .consume(applying, &admitted.principal, &run.plan_id)
                {
                    tracing::warn!(
                        event.name = "host.plan_unconsumed",
                        component = super::COMPONENT,
                        error = %error,
                        "a reset plan could not be marked consumed; the identity is reset"
                    );
                }
                let host_id = uuid_text(&reset.host_id);
                Ok(Applied {
                    revision: 1,
                    target: Some(format!("host:{host_id}")),
                    value: IdentityResetDone {
                        receipt: self.receipt(applying.operation_id(), 1),
                        old_host_id: old.clone(),
                        host_id,
                        fingerprint: reset.fingerprint,
                        witness: reset.witness,
                        ended: ended.clone(),
                        orphaned: orphaned.clone(),
                        restart_required: true,
                    },
                })
            },
            |_, _, _| Err(unreachable_reconciliation(RESET_RUN)),
        )?;
        self.health.lifecycle().degrade(
            permguard_core::lifecycle::HOST,
            "identity",
            "the Host identity was reset: restart the process to serve the new one",
        );
        tracing::warn!(
            event.name = "host.identity_reset",
            component = super::COMPONENT,
            old_host_id = %done.old_host_id,
            host_id = %done.host_id,
            orphaned = done.orphaned.len(),
            "the Host identity was reset; the process signs nothing more and needs a restart"
        );
        Ok(done)
    }
}

#[cfg(test)]
mod tests;
