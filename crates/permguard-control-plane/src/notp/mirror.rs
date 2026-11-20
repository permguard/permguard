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
    FetchObjectsRequest, GetRefRequest, LedgerIds, ListLedgersAnswer, ListLedgersRequest,
    ListedLedger, MAX_LISTED_LEDGERS, MirrorOperation, MirrorRequest, NegotiatePullRequest,
};

use super::NotpFacade;

/// The contract version this handler speaks.
pub const VERSION: u64 = 1;

/// Serves `policy.mirror` reads from the facade.
pub struct Mirror {
    pub facade: Arc<NotpFacade>,
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
        // What the session reads: below its resource only where the task's signed selector reaches
        // below it (WP-7.2a); an exact selector reads exactly its own resource.
        let reading = if context.selector.covers_descendants() {
            Selector::under(session)
        } else {
            Selector::exactly(session)
        };
        // The listing (WP-7.2a): every ledger the session reads, by id, and nothing beside it.
        if request.operation == MirrorOperation::ListLedgers {
            let held = if request.body.is_empty() {
                None
            } else {
                Some(
                    ListLedgersRequest::decode(&request.body)
                        .map_err(|error| rejected(format!("a listing: {error}")))?
                        .held,
                )
            };
            return self.listed(&reading, held.as_deref()).and_then(|answer| {
                answer.encode().map_err(|error| Refusal {
                    code: codes::notp::NOTP_FAILED,
                    reason: format!("encoding the listing: {error}"),
                })
            });
        }
        let forbidden = || Refusal {
            code: codes::common::FORBIDDEN,
            reason: format!(
                "the ledger {}/{} is not under the session's resource {}",
                request.zone, request.ledger, context.resource
            ),
        };
        if !reading.contains(&Resource::ledger(
            crate::PLANE,
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
            permguard_core::encoding::hex(&context.membership_id)
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
            // Answered above, before any ledger is resolved.
            MirrorOperation::ListLedgers => Err(rejected("a listing names no ledger")),
        }
    }
}

impl Mirror {
    /// Every ledger `under` covers, sorted by `(zone_id, ledger_id)`; past the bound, the first
    /// ones and `complete` false. When the member named the ledgers it `held`, the answer names
    /// those among them this Control Plane deleted, from their tombstones or their zone's, and
    /// only under `under`: a member learns nothing of a ledger outside its task (BUG-0192).
    fn listed(
        &self,
        under: &Selector,
        held: Option<&[LedgerIds]>,
    ) -> Result<ListLedgersAnswer, Refusal> {
        let catalog = &self.facade.catalog;
        let mut ledgers = Vec::new();
        for zone in catalog
            .list_zones()
            .map_err(|error| refused(crate::catalog::api_error(error)))?
        {
            for ledger in catalog
                .list_ledgers(&permguard_core::catalog::Selector::Id(zone.id.clone()))
                .map_err(|error| refused(crate::catalog::api_error(error)))?
            {
                if under.contains(&Resource::ledger(crate::PLANE, &zone.id, &ledger.id)) {
                    ledgers.push(ListedLedger {
                        zone_id: zone.id.clone(),
                        zone_name: zone.name.clone(),
                        ledger_id: ledger.id,
                        ledger_name: ledger.name,
                    });
                }
            }
        }
        let mut answer = bounded(ledgers);
        if let Some(held) = held {
            let mut deleted = Vec::new();
            for ids in held {
                if !under.contains(&Resource::ledger(
                    crate::PLANE,
                    &ids.zone_id,
                    &ids.ledger_id,
                )) {
                    continue;
                }
                let gone = catalog
                    .ledger_tombstone(&ids.zone_id, &ids.ledger_id)
                    .map_err(|error| refused(crate::catalog::api_error(error)))?
                    .is_some()
                    || catalog
                        .zone_tombstone(&ids.zone_id)
                        .map_err(|error| refused(crate::catalog::api_error(error)))?
                        .is_some();
                if gone {
                    deleted.push(ids.clone());
                }
            }
            answer.deleted = Some(deleted);
        }
        Ok(answer)
    }
}

/// `ledgers` as a listing: sorted by `(zone_id, ledger_id)`, the first `MAX_LISTED_LEDGERS`, and
/// `complete` only when nothing was left out.
fn bounded(mut ledgers: Vec<ListedLedger>) -> ListLedgersAnswer {
    ledgers.sort_by(|left, right| {
        (&left.zone_id, &left.ledger_id).cmp(&(&right.zone_id, &right.ledger_id))
    });
    let complete = ledgers.len() <= MAX_LISTED_LEDGERS;
    ledgers.truncate(MAX_LISTED_LEDGERS);
    ListLedgersAnswer {
        ledgers,
        complete,
        deleted: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(at: usize) -> ListedLedger {
        ListedLedger {
            zone_id: "zone".to_owned(),
            zone_name: "acme".to_owned(),
            ledger_id: format!("{at:06}"),
            ledger_name: format!("ledger-{at}"),
        }
    }

    /// WP-7.2a: a listing up to the bound is complete; one past it keeps the first ones, sorted,
    /// and says it is not.
    #[test]
    fn a_listing_past_its_bound_keeps_the_first_and_says_it_is_not_complete() {
        let full = bounded((0..MAX_LISTED_LEDGERS).rev().map(ledger).collect());
        assert!(full.complete);
        assert_eq!(full.ledgers.len(), MAX_LISTED_LEDGERS);
        assert_eq!(full.ledgers[0], ledger(0), "sorted");

        let past = bounded((0..=MAX_LISTED_LEDGERS).rev().map(ledger).collect());
        assert!(!past.complete);
        assert_eq!(past.ledgers.len(), MAX_LISTED_LEDGERS);
        assert_eq!(
            past.ledgers.last(),
            Some(&ledger(MAX_LISTED_LEDGERS - 1)),
            "the first ones are kept"
        );
    }
}
