// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The members serving a ledger, as `GetLedger` shows them beside it (WP-4.4; the catalog
//! contract's `serving_members[]`).
//!
//! The Host's memberships say who is assigned and what each member last reported; this module
//! shapes that for both transports, the same fields on each. Assignment and observations, never
//! a coordinator's guarantee that a member serves now; declared assurance is never rendered as
//! verified, and no evidence leaves the Host.

use serde::Serialize;

use permguard_host::api::members::ServingMemberView;

/// One accepted claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServingClaim {
    pub control: String,
    pub class: String,
    pub by: String,
}

/// A binding's status, without its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServingAssurance {
    pub verdict: String,
    pub current: bool,
    pub policy_revision: String,
    pub claims: Vec<ServingClaim>,
    pub expires_at: String,
}

/// A member's last report of the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServingProgress {
    pub report_seq: u64,
    pub reported_at: String,
    pub received_at: String,
    pub state: Option<String>,
    pub checkpoint_digest: Option<String>,
    pub stale: bool,
}

/// One member assigned to serve the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServingMember {
    pub host_id: String,
    pub membership_id: String,
    pub task_id: String,
    pub declared_assurance: String,
    pub assurance_binding_status: Option<ServingAssurance>,
    pub lease_state: String,
    pub last_session_at: Option<String>,
    pub progress: Option<ServingProgress>,
}

impl From<ServingMemberView> for ServingMember {
    fn from(view: ServingMemberView) -> Self {
        Self {
            host_id: view.host_id,
            membership_id: view.membership_id,
            task_id: view.task_id,
            declared_assurance: view.declared_assurance,
            assurance_binding_status: view.assurance_binding_status.map(|binding| {
                ServingAssurance {
                    verdict: binding.verdict,
                    current: binding.current,
                    policy_revision: binding.policy_revision,
                    claims: binding
                        .claims
                        .into_iter()
                        .map(|claim| ServingClaim {
                            control: claim.control,
                            class: claim.class,
                            by: claim.by,
                        })
                        .collect(),
                    expires_at: binding.expires_at,
                }
            }),
            lease_state: view.lease_state,
            last_session_at: view.last_session_at,
            progress: view.progress.map(|progress| ServingProgress {
                report_seq: progress.report_seq,
                reported_at: progress.reported_at,
                received_at: progress.received_at,
                state: progress.state,
                checkpoint_digest: progress.checkpoint_digest,
                stale: progress.stale,
            }),
        }
    }
}

/// A ledger with the members serving it: what `GET …/ledgers/{ledger}` answers.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerServed {
    #[serde(flatten)]
    pub ledger: permguard_core::Ledger,
    pub serving_members: Vec<ServingMember>,
}
