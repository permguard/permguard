// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `policy.mirror` task handler (WP-7.12): a member pulls over the Host task transport through
//! the same NOTP read facade the public surfaces call.
//!
//! The Host authorized the task session: its membership is active, its task names the resource
//! and the session's lease the resource it reads under. Here the ledger a message names is
//! resolved and must lie under that resource before anything is read. The member's transfer
//! sessions are bound to its membership, so one member cannot name another's transfer.

use std::sync::Arc;

use permguard_core::authz::{Resource, Selector};
use permguard_core::{ApiError, codes};
use permguard_host::membership::task::{TaskContext, TaskHandler};
use permguard_host::session::Refusal;
use permguard_notp::{
    FetchObjectsRequest, GetRefRequest, MirrorOperation, MirrorRequest, NegotiatePullRequest,
};

use super::NotpFacade;

/// The contract version this handler speaks.
pub const VERSION: u64 = 1;

/// Serves `policy.mirror` reads from the facade.
pub(crate) struct Mirror {
    pub(crate) facade: Arc<NotpFacade>,
}

fn refused(error: ApiError) -> Refusal {
    Refusal {
        code: error.code(),
        reason: error.to_string(),
    }
}

fn rejected(reason: impl Into<String>) -> Refusal {
    Refusal {
        code: codes::notp::BODY_REJECTED,
        reason: reason.into(),
    }
}

impl TaskHandler for Mirror {
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let request = MirrorRequest::decode(body)
            .map_err(|error| rejected(format!("not a policy.mirror message: {error}")))?;
        // The ledger is under the resource the session reads, named by its ids, before the
        // catalog is asked anything: a member reads what its task names, and learns nothing of
        // what lies beside it.
        let session = Resource::parse(&context.resource)
            .map_err(|error| rejected(format!("the session's resource: {error}")))?;
        let forbidden = || Refusal {
            code: codes::common::FORBIDDEN,
            reason: format!(
                "the ledger {}/{} is not under the session's resource {}",
                request.zone, request.ledger, context.resource
            ),
        };
        if !Selector::under(session).contains(&Resource::ledger(
            crate::service::PLANE,
            &request.zone,
            &request.ledger,
        )) {
            return Err(forbidden());
        }
        let (zone, ledger) = self
            .facade
            .ledger_ids(&request.zone, &request.ledger)
            .map_err(refused)?;
        if (zone.as_str(), ledger.as_str()) != (request.zone.as_str(), request.ledger.as_str()) {
            // A name that resolves to an id: the message names ledgers by id only.
            return Err(forbidden());
        }
        let caller = format!(
            "membership:{}",
            crate::transfer::hex(&context.membership_id)
        );
        let encoded = |result: Result<Vec<u8>, permguard_notp::WireError>| {
            result.map_err(|error| Refusal {
                code: codes::notp::NOTP_FAILED,
                reason: format!("encoding the answer: {error}"),
            })
        };
        match request.operation {
            MirrorOperation::GetRef => {
                let asked = GetRefRequest::decode(&request.body)
                    .map_err(|error| rejected(format!("a ref read: {error}")))?;
                encoded(
                    self.facade
                        .get_ref_as(&caller, &zone, &ledger, &asked.r#ref)
                        .map_err(refused)?
                        .encode(),
                )
            }
            MirrorOperation::NegotiatePull => {
                let asked = NegotiatePullRequest::decode(&request.body)
                    .map_err(|error| rejected(format!("a pull negotiation: {error}")))?;
                encoded(
                    self.facade
                        .negotiate_pull_as(&caller, &zone, &ledger, &asked)
                        .map_err(refused)?
                        .encode(),
                )
            }
            MirrorOperation::FetchObjects => {
                let asked = FetchObjectsRequest::decode(&request.body)
                    .map_err(|error| rejected(format!("a fetch: {error}")))?;
                encoded(
                    self.facade
                        .fetch_as(&caller, &zone, &ledger, &asked)
                        .map_err(refused)?
                        .encode(),
                )
            }
            MirrorOperation::KeyRing => self.facade.keyring().map_err(refused),
        }
    }
}
