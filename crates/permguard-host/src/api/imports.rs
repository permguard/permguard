// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An operator's acceptance of a gap in imported history (BUG-0128, owner decision of
//! 2026-11-20).
//!
//! | Route                                | What                                                     |
//! | ------------------------------------ | -------------------------------------------------------- |
//! | `POST /host/v1/imports/gaps/accept`  | the open gaps of one origin's run over one ledger, marked |
//! |                                      | accepted: `shared-bounded` decides again without them    |
//!
//! A gap is history this Host will never hold: the coordinator had deleted it, it did not
//! verify, or its origin forked. `shared-bounded` withholds its decisions while one is open, and
//! waiting never closes it. An operator who knows what the missing records were accepts it here,
//! under `membership.admin`, with a reason: the gap stays on the record, marked when and by whom,
//! and the acceptance is audited. The run is still not imported past it.

use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, Resource, operations};
use permguard_core::{ErrorClass, codes};

use super::{HostApi, Mutation, Receipt, Refusal};
use crate::operations::mutation::{Applied, Failure};

/// The operation an acceptance runs as, in the memberships' domain.
pub const ACCEPT: &str = "imports.gaps.accept";
/// The `security` action it is recorded under.
pub const AUDIT_GAP_ACCEPTED: &str = "host.imports.gap_accepted";

/// `POST /host/v1/imports/gaps/accept`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptImportGaps {
    #[serde(default)]
    pub request_id: String,
    /// The ledger the gaps are of: `plane/data/zone/<zone id>/ledger/<ledger id>`.
    pub resource: String,
    /// The origin Host, 32 hex digits.
    pub origin: String,
    /// The origin's run, 32 hex digits.
    pub run: String,
    /// Why the missing history may be decided without: printable, at most 256 bytes.
    pub reason: String,
}

/// What an acceptance answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportGapsAccepted {
    pub receipt: Receipt,
    /// How many open gaps of the run it accepted.
    pub accepted: u64,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        message,
    )
}

fn id16(text: &str, what: &str) -> Result<[u8; 16], Refusal> {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .filter_map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect();
    if text.len() != 32 {
        return Err(invalid(format!("`{what}` is 32 hex digits")));
    }
    bytes
        .try_into()
        .map_err(|_| invalid(format!("`{what}` is 32 hex digits")))
}

impl HostApi {
    /// `POST /host/v1/imports/gaps/accept`: the open gaps of `accept.origin`'s run `accept.run`
    /// over the ledger `accept.resource`, accepted by the caller, under `membership.admin`.
    pub async fn accept_import_gaps(
        &self,
        actor: &Actor,
        accept: AcceptImportGaps,
    ) -> Result<ImportGapsAccepted, Refusal> {
        let admitted = self.admit(actor, operations::MEMBERSHIP_ADMIN)?;
        let mutation = Mutation {
            request_id: accept.request_id.clone(),
            expected_revision: None,
        };
        // Every mutation names its request id before anything else of it is judged.
        mutation.validated()?;
        if accept.reason.is_empty()
            || accept.reason.len() > 256
            || accept.reason.chars().any(char::is_control)
        {
            return Err(invalid("`reason` is printable text of 1 to 256 bytes"));
        }
        if crate::audit::looks_secret(&accept.reason) {
            return Err(invalid(super::members::REASON_SECRET));
        }
        let resource = Resource::parse(&accept.resource)
            .ok()
            .filter(
                |resource| matches!(resource, Resource::Ledger { plane, .. } if plane == "data"),
            )
            .ok_or_else(|| {
                invalid("`resource` is a Data Plane ledger, `plane/data/zone/<id>/ledger/<id>`")
            })?;
        let origin = id16(&accept.origin, "origin")?;
        let run = id16(&accept.run, "run")?;
        let imports = self.imports.as_ref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "this Host imports no history: it has no gap to accept",
            )
        })?;
        let open = || -> Result<u64, Refusal> {
            let state = imports
                .import_state(&resource)
                .map_err(|error| {
                    Refusal::new(ErrorClass::Unavailable, codes::common::UNAVAILABLE, error)
                })?
                .ok_or_else(|| {
                    Refusal::new(
                        ErrorClass::NotFound,
                        codes::common::NOT_FOUND,
                        "this Host keeps no import of that ledger",
                    )
                })?;
            let open = state.open_gaps(&origin, &run);
            if open == 0 {
                return Err(Refusal::new(
                    ErrorClass::NotFound,
                    codes::common::NOT_FOUND,
                    "no open gap of that origin's run over that ledger",
                ));
            }
            Ok(open)
        };
        let now = self.time.now_secs();
        let principal = admitted.principal.clone();
        let target = format!("{}/{}/{}", accept.resource, accept.origin, accept.run);
        self.transact(
            crate::membership::DOMAIN,
            &admitted.principal,
            ACCEPT,
            AUDIT_GAP_ACCEPTED,
            &mutation,
            &accept,
            Some(target.clone()),
            || open().map(|_| ()),
            |applying| {
                open().map_err(Failure::Refused)?;
                let mut state = imports
                    .import_state(&resource)
                    .map_err(|error| Failure::Refused(invalid(error)))?
                    .ok_or_else(|| Failure::Refused(invalid("the import vanished")))?;
                let accepted = state.accept_gaps(&origin, &run, now, principal.as_str());
                imports
                    .keep_import_state(&resource, &state)
                    .map_err(|error| {
                        Failure::Refused(Refusal::new(
                            ErrorClass::Unavailable,
                            codes::common::UNAVAILABLE,
                            error,
                        ))
                    })?;
                tracing::warn!(
                    event.name = "host.imports.gap_accepted",
                    component = "host",
                    resource = %accept.resource,
                    origin = %accept.origin,
                    run = %accept.run,
                    accepted,
                    reason = %accept.reason,
                    "an operator accepted a gap of imported history: `shared-bounded` decides \
                     without it"
                );
                Ok(Applied {
                    revision: state.gaps.len() as u64,
                    target: Some(target.clone()),
                    value: ImportGapsAccepted {
                        receipt: self.receipt(applying.operation_id(), state.gaps.len() as u64),
                        accepted,
                    },
                })
            },
            |operation_id, revision, _| {
                Ok(ImportGapsAccepted {
                    receipt: self.receipt(operation_id, revision),
                    accepted: 0,
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::api::testing::{actor, admin, facade, grant_to};
    use crate::composition::{ImportOrigin, Imported, StreamImport};
    use crate::membership::import::{Gap, RETENTION, State};

    const LEDGER: &str =
        "plane/data/zone/0198f2aa000070008000000000000001/ledger/0198f3bb000070008000000000000002";

    /// The member's consumer, as far as its import state.
    #[derive(Default)]
    struct Held(Mutex<Option<State>>);

    impl StreamImport for Held {
        fn held(&self, _: &Resource, _: &[u8; 16], _: &[u8; 16]) -> Result<u64, String> {
            Ok(0)
        }
        fn import(&self, _: &Resource, _: &ImportOrigin<'_>, _: &[u8]) -> Result<Imported, String> {
            Err("not imported here".to_owned())
        }
        fn import_state(&self, _: &Resource) -> Result<Option<State>, String> {
            Ok(self.0.lock().expect("lock").clone())
        }
        fn keep_import_state(&self, _: &Resource, state: &State) -> Result<(), String> {
            *self.0.lock().expect("lock") = Some(state.clone());
            Ok(())
        }
    }

    fn gap(run: u8, from: u64) -> Gap {
        Gap {
            origin: [1; 16],
            run: [run; 16],
            from,
            through: Some(from + 1),
            reason: RETENTION.to_owned(),
            detected_at: 1,
            revision: [2; 32],
            accepted_at: None,
            accepted_by: None,
        }
    }

    fn accept(request_id: &str, run: u8, reason: &str) -> AcceptImportGaps {
        AcceptImportGaps {
            request_id: request_id.to_owned(),
            resource: LEDGER.to_owned(),
            origin: "01".repeat(16),
            run: format!("{run:02x}").repeat(16),
            reason: reason.to_owned(),
        }
    }

    /// BUG-0128: an operator holding `membership.admin` accepts the open gaps of one origin's run,
    /// which stay on the record marked when and by whom; another run's gaps are untouched; a run
    /// with none open, a caller without the grant and a reason that is empty are refused.
    #[tokio::test]
    async fn an_operator_accepts_the_open_gaps_of_one_run_and_they_stay_marked() {
        let held = Arc::new(Held::default());
        *held.0.lock().expect("lock") = Some(State {
            membership_id: [3; 16],
            revision: [2; 32],
            checkpoint: Vec::new(),
            verified_at: 1,
            gaps: vec![gap(4, 1), gap(4, 9), gap(5, 1)],
        });
        let api = facade("imports-accept").with_imports(Arc::clone(&held) as Arc<dyn StreamImport>);

        let accepted = api
            .accept_import_gaps(
                &admin(),
                accept("a1", 4, "history before November is not needed"),
            )
            .await
            .expect("accepted");
        assert_eq!(accepted.accepted, 2);
        let state = held.0.lock().expect("lock").clone().expect("kept");
        assert_eq!(state.open_gaps(&[1; 16], &[4; 16]), 0);
        assert_eq!(
            state.open_gaps(&[1; 16], &[5; 16]),
            1,
            "another run's gap stays open"
        );
        assert_eq!(state.gaps.len(), 3, "accepted gaps stay on the record");
        assert!(
            state
                .gaps
                .iter()
                .filter(|gap| gap.run == [4; 16])
                .all(|gap| gap.accepted_at.is_some() && gap.accepted_by.is_some())
        );
        assert_eq!(
            State::decode(&state.encode().expect("encodes")).expect("decodes"),
            state
        );

        let refused = api
            .accept_import_gaps(&admin(), accept("a2", 4, "again"))
            .await
            .expect_err("none open");
        assert!(matches!(refused, Refusal::Api(_)), "{refused:?}");
        let refused = api
            .accept_import_gaps(&admin(), accept("a3", 5, ""))
            .await
            .expect_err("no reason");
        assert!(matches!(refused, Refusal::Api(_)), "{refused:?}");
        grant_to("sa:reader", &[operations::LIFECYCLE_READ], "host/*");
        let refused = api
            .accept_import_gaps(&actor("sa:reader"), accept("a4", 5, "mine"))
            .await
            .expect_err("no grant");
        assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
        assert_eq!(
            held.0
                .lock()
                .expect("lock")
                .clone()
                .expect("kept")
                .open_gaps(&[1; 16], &[5; 16]),
            1
        );
    }
}
