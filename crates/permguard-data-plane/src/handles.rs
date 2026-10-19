// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane declares to the Host, and the handles it gets back (WP-2.1, P1).
//!
//! | Declared                              | Handle                           | Used by                        |
//! | ------------------------------------- | -------------------------------- | ------------------------------ |
//! | signs `DecisionBatchV1`               | `Signer<DecisionBatchV1>`        | the decision shipper, the JWKS |
//! | signs `EventBatchV1`                  | `Signer<EventBatchV1>`           | the event shipper              |
//! | audit schema [`DataPlaneAudit`]       | `AuditHandle<DataPlaneAudit>`    | decisions, mirrors             |
//! | zone keys `decision.commitment`       | `ZoneHandle`                     | input tags, per ledger         |
//! | zone keys `audit.pseudonym`           | `ZoneHandle`                     | decision subjects, per zone    |
//! | produces `data/decisions` (WP-6.1)    | `StreamProducer`                 | the decision log               |
//! | task contracts (WP-4.4)               | none                             | approval's task capability     |
//!
//! The plane never sees a key manager, the audit recorder, the secret store, a root or a key's
//! bytes: only these (WP-3.3 for the zone keys).

use std::sync::Arc;

use permguard_core::keys::PublicSet;
use permguard_core::{Config, PlaneContext};
use permguard_host::composition::{
    AuditHandle, AuditSchema, DecisionBatchV1, Declaration, EventBatchV1, Registration,
};
use permguard_host::secrets::{ZoneHandle, ZonePurpose};

use crate::service::PLANE;

/// Every action this plane records to the audit trail.
pub struct DataPlaneAudit;

impl AuditSchema for DataPlaneAudit {
    const NAME: &'static str = "data-plane.v1";
    const ACTIONS: &'static [&'static str] = &["authz.decision", "ledger.synchronized"];
}

/// This plane's audit handle.
pub type Audit = AuditHandle<DataPlaneAudit>;

/// What this plane declares to the Host under `config`: the zone keys of input tags and of the
/// subjects' pseudonyms, and the decision stream it produces, only when the decision log is on, so
/// a plane that keeps no log MACs under nothing (WP-3.3) and appends to no stream (WP-6.1); the
/// event stream only when it serves the temporal interface (WP-6.2a).
pub(crate) fn declaration(config: &Config) -> Declaration {
    use permguard_host::membership::record::TaskType;

    // The task contracts this plane takes part in as a member (WP-4.4, owner decision); the
    // member's Host consumes `events.import` itself (WP-6.2c1).
    let declaration = Declaration::new(PLANE)
        .signs::<DecisionBatchV1>()
        .signs::<EventBatchV1>()
        .audits::<DataPlaneAudit>()
        .uses_task(TaskType::PolicyMirror, 1)
        .handles_task(TaskType::DecisionsShip, 1)
        .handles_task(TaskType::EventsShip, 1);
    let declaration = if crate::temporal::served(config) {
        declaration.produces_stream(permguard_events::stream::STREAM)
    } else {
        declaration
    };
    if config.log_enabled() {
        declaration
            .uses_zone_key(ZonePurpose::DecisionCommitment)
            .uses_zone_key(ZonePurpose::AuditPseudonym)
            .produces_stream(permguard_decisions::stream::STREAM)
    } else {
        declaration
    }
}

fn registration(context: &PlaneContext<'_>) -> Option<Arc<Registration>> {
    context.handles::<Registration>()
}

/// The Host's authorization, which every route of this plane decides with (WP-2.4). A plane the
/// Host did not register decides with a closed one: nothing is allowed.
pub(crate) fn authorization(
    context: &PlaneContext<'_>,
) -> Arc<permguard_host::composition::Authorization> {
    registration(context).map_or_else(
        || Arc::new(permguard_host::composition::Authorization::closed()),
        |registration| registration.authorization(),
    )
}

/// The audit handle, when an audit recorder is composed.
pub(crate) fn audit(context: &PlaneContext<'_>) -> Option<Audit> {
    registration(context)?
        .audit::<DataPlaneAudit>()
        .ok()
        .flatten()
}

/// The decision batch signer, when the plane's signing ring is composed.
pub(crate) fn decision_signer(
    context: &PlaneContext<'_>,
) -> Option<Arc<dyn permguard_decisions::envelope::BatchSigner>> {
    let signer = registration(context)?
        .signer::<DecisionBatchV1>()
        .ok()
        .flatten()?;
    Some(Arc::new(signer))
}

/// The event batch signer, when the plane's signing ring is composed.
pub(crate) fn event_signer(
    context: &PlaneContext<'_>,
) -> Option<Arc<dyn permguard_events::envelope::BatchSigner>> {
    let signer = registration(context)?
        .signer::<EventBatchV1>()
        .ok()
        .flatten()?;
    Some(Arc::new(signer))
}

/// This plane's public set, to publish, when its signing ring is composed.
pub(crate) fn public_keys(context: &PlaneContext<'_>) -> Option<Arc<dyn PublicSet>> {
    let signer = registration(context)?
        .signer::<DecisionBatchV1>()
        .ok()
        .flatten()?;
    Some(Arc::new(signer))
}

/// An audit handle over `recorder`, for a test that needs one without composing a server.
#[cfg(test)]
pub(crate) fn audit_for_tests(recorder: permguard_core::AuditRecorder) -> Audit {
    permguard_host::composition::Host::builder()
        .audit(recorder)
        .build()
        .register(Declaration::new(PLANE).audits::<DataPlaneAudit>())
        .ok()
        .and_then(|registration| registration.audit::<DataPlaneAudit>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared schema with a composed recorder"))
}

/// The producer of the decision stream, when the Host composes a stream engine and the log is on
/// (WP-6.1).
pub(crate) fn decision_producer(
    context: &PlaneContext<'_>,
) -> Option<permguard_host::composition::StreamProducer> {
    registration(context)?
        .stream_producer(permguard_decisions::stream::STREAM)
        .ok()
        .flatten()
}

/// The Host's producer of the event stream, when this plane serves the temporal interface and an
/// engine is composed (WP-6.2a).
pub(crate) fn event_producer(
    context: &PlaneContext<'_>,
) -> Option<permguard_host::composition::StreamProducer> {
    registration(context)?
        .stream_producer(permguard_events::stream::STREAM)
        .ok()
        .flatten()
}

/// This Host's `host_id`, when the composition knows it: what the decision stream is named by.
pub(crate) fn host_id(context: &PlaneContext<'_>) -> Option<[u8; 16]> {
    registration(context)?.host_id()
}

/// The zone keys of `purpose` the Host holds for this plane: `None` without them, never another
/// purpose's.
pub(crate) fn zone_key(
    context: &PlaneContext<'_>,
    purpose: ZonePurpose,
) -> Option<Arc<ZoneHandle>> {
    registration(context)?.zone_key(purpose).ok().flatten()
}

#[cfg(test)]
mod tests {
    use permguard_host::audit::{DATA, REGISTRY};
    use permguard_host::composition::AuditSchema as _;

    use super::DataPlaneAudit;

    /// The Host refuses an action its registry does not name, which would fail the Plane's call.
    #[test]
    fn every_action_of_the_schema_is_registered_with_the_host_under_this_plane() {
        for action in DataPlaneAudit::ACTIONS {
            let schema = REGISTRY
                .iter()
                .find(|schema| schema.action == *action)
                .unwrap_or_else(|| panic!("`{action}` is not registered with the Host"));
            assert_eq!(schema.root, DATA, "{action}");
        }
    }
}

#[cfg(test)]
mod task_contract_tests {
    #![allow(clippy::expect_used)]

    use permguard_host::membership::record::{ContractRole, TaskType};

    /// The task contracts this plane registers, version 1 (WP-4.4, owner decision).
    #[test]
    fn the_plane_declares_its_task_contracts() {
        let declaration = super::declaration(&permguard_core::Config::default());
        let contracts: Vec<(TaskType, ContractRole)> = declaration
            .task_contracts()
            .iter()
            .map(|contract| {
                assert_eq!(contract.version, 1);
                (contract.task_type, contract.role)
            })
            .collect();
        assert_eq!(
            contracts,
            vec![
                (TaskType::PolicyMirror, ContractRole::Consumer),
                (TaskType::DecisionsShip, ContractRole::Provider),
                (TaskType::EventsShip, ContractRole::Provider),
            ]
        );
    }
}
