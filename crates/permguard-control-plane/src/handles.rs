// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane declares to the Host, and the handles it gets back (WP-2.1, P1).
//!
//! | Declared                          | Handle                          | Used by                          |
//! | --------------------------------- | ------------------------------- | -------------------------------- |
//! | signs `HeadStatementV1`           | `Signer<HeadStatementV1>`       | NOTP head statements, the JWKS   |
//! | signs `ImportCheckpointV1`        | `Signer<ImportCheckpointV1>`    | `events.import` checkpoints      |
//! | signs `LedgerExportV1`            | `Signer<LedgerExportV1>`        | ledger and zone export manifests |
//! | reads the public set of `data.attest` | `PublicKeys`                | verifying a local producer       |
//! | audit schema [`ControlPlaneAudit`] | `AuditHandle<ControlPlaneAudit>` | catalog, NOTP, GC                |
//! | task contracts (WP-4.4)           | none                            | approval's task capability       |
//!
//! The plane never sees a key manager, the audit recorder or the secret store: only these.

use std::sync::Arc;

use permguard_core::PlaneContext;
use permguard_core::keys::PublicSet;
use permguard_host::composition::{
    AuditHandle, AuditSchema, DATA_ATTEST, Declaration, HeadStatementV1, ImportCheckpointV1,
    LedgerExportV1, Registration, Signer,
};

use crate::service::PLANE;

/// Every action this plane records to the audit trail.
pub struct ControlPlaneAudit;

impl AuditSchema for ControlPlaneAudit {
    const NAME: &'static str = "control-plane.v1";
    const ACTIONS: &'static [&'static str] = &[
        "zone.created",
        "zone.renamed",
        "zone.deleted",
        "zone.create.refused",
        "zone.rename.refused",
        "zone.delete.refused",
        "ledger.created",
        "ledger.renamed",
        "ledger.deleted",
        "ledger.create.refused",
        "ledger.rename.refused",
        "ledger.delete.refused",
        "ledger.exported",
        "zone.exported",
        "zone.archive_imported",
        "notp.push.negotiate.refused",
        "notp.upload.refused",
        "notp.push.commit.refused",
        "store.swept",
    ];
}

/// This plane's audit handle.
pub(crate) type Audit = AuditHandle<ControlPlaneAudit>;

/// What this plane declares to the Host.
pub(crate) fn declaration() -> Declaration {
    use permguard_host::membership::record::TaskType;

    // The task contracts this plane serves at the Host's listener (WP-4.4, owner decision): their
    // bodies answer `not_served_yet` until their packages bring the semantics.
    Declaration::new(PLANE)
        .signs::<HeadStatementV1>()
        // The observation checkpoints of `events.import` (WP-6.2c1).
        .signs::<ImportCheckpointV1>()
        // The manifest of an export, signed by the Host under `host.operations` (WP-7.10).
        .signs::<LedgerExportV1>()
        .reads_public_keys(DATA_ATTEST)
        .audits::<ControlPlaneAudit>()
        .mutates(crate::store::REFS_DOMAIN)
        // Every catalog mutation is an operation of the transaction (WP-7.3a).
        .mutates(crate::catalog::CATALOG_DOMAIN)
        // The garbage collection keeps what a hold names (WP-7.3c).
        .reads_holds()
        .handles_task(TaskType::PolicyMirror, 1)
        .handles_task(TaskType::EventsImport, 1)
        .uses_task(TaskType::DecisionsShip, 1)
        .uses_task(TaskType::EventsShip, 1)
        // The public decision reads answer from the Host's consumer (WP-6.1b).
        .reads_stream(permguard_decisions::stream::STREAM)
        .reads_stream(permguard_events::stream::STREAM)
}

pub(crate) fn registration(context: &PlaneContext<'_>) -> Option<Arc<Registration>> {
    context.handles::<Registration>()
}

/// This Host's `host_id`, the salt of the cursor keys this plane derives from its stores' roots
/// (WP-3.3); `None` when no Host registered the plane.
pub(crate) fn host_id(context: &PlaneContext<'_>) -> Option<[u8; 16]> {
    registration(context)?.host_id()
}

/// The Host's consumer of the event stream, which the public event reads answer from (WP-6.2b);
/// `None` when the Host composes no stream engine consuming it.
pub(crate) fn event_consumer(
    context: &PlaneContext<'_>,
) -> Option<permguard_host::composition::StreamConsumer> {
    match registration(context)?.stream_consumer(permguard_events::stream::STREAM) {
        Ok(consumer) => consumer,
        Err(error) => {
            tracing::error!(
                event.name = "events.consumer_undeclared",
                component = "control-plane",
                error = %error,
                "the event reads cannot reach the Host's consumer"
            );
            None
        }
    }
}

/// The Host's consumer of the decision stream, which the public decision reads answer from
/// (WP-6.1b); `None` when the Host composes no stream engine consuming it.
pub(crate) fn decision_consumer(
    context: &PlaneContext<'_>,
) -> Option<permguard_host::composition::StreamConsumer> {
    match registration(context)?.stream_consumer(permguard_decisions::stream::STREAM) {
        Ok(consumer) => consumer,
        Err(error) => {
            // The declaration and this lookup name the same stream: a mismatch turns the Host
            // reads off, and is said rather than swallowed.
            tracing::error!(
                event.name = "decisions.consumer_undeclared",
                component = "control-plane",
                error = %error,
                "the decision reads cannot reach the Host's consumer"
            );
            None
        }
    }
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

/// The mutation transaction the ref updates run in (WP-3.6), when the Host composes one.
pub(crate) fn ref_mutations(
    context: &PlaneContext<'_>,
) -> Option<permguard_host::composition::MutationHandle> {
    registration(context)?
        .mutations(crate::store::REFS_DOMAIN)
        .ok()
        .flatten()
}

/// The Host's holds (WP-7.3c): `Ok(None)` for a plane no Host registered, which has no holds to
/// keep; an error for a registered plane, which declared it reads them, handed none (after the
/// review).
pub(crate) fn holds(
    context: &PlaneContext<'_>,
) -> Result<Option<std::sync::Arc<permguard_host::holds::HoldStore>>, ()> {
    match registration(context) {
        None => Ok(None),
        Some(registration) => registration.holds().map(Some).ok_or(()),
    }
}

/// The mutation transaction the catalog's mutations run in (WP-7.3a), when the Host composes
/// one.
pub(crate) fn catalog_mutations(
    context: &PlaneContext<'_>,
) -> Option<permguard_host::composition::MutationHandle> {
    registration(context)?
        .mutations(crate::catalog::CATALOG_DOMAIN)
        .ok()
        .flatten()
}

/// A mutation transaction of the catalog over an offline engine of its own on a fresh volume
/// under `directory`, for a test.
#[cfg(test)]
pub(crate) fn catalog_mutations_for_tests(
    directory: &std::path::Path,
) -> permguard_host::composition::MutationHandle {
    let volume = permguard_host::storage::volume::Volume::claim(
        directory,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .unwrap_or_else(|error| unreachable!("a test volume is claimed: {error}"));
    let engine = permguard_host::operations::mutation::Mutations::open_offline(&volume, "test")
        .unwrap_or_else(|error| unreachable!("a test mutation transaction opens: {error}"));
    permguard_host::composition::MutationHandle::new(
        std::sync::Arc::new(engine),
        crate::catalog::CATALOG_DOMAIN,
    )
}

/// A mutation transaction of the catalog over `projection` instead of an audit engine, on the
/// volume under `directory`, fresh or reopened: for a test that sees, or refuses, the phases.
#[cfg(test)]
pub(crate) fn catalog_mutations_over(
    directory: &std::path::Path,
    projection: std::sync::Arc<dyn permguard_host::operations::mutation::Projection>,
) -> permguard_host::composition::MutationHandle {
    let volume = permguard_host::storage::volume::Volume::claim(
        directory,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .unwrap_or_else(|error| unreachable!("a test volume is claimed: {error}"));
    let engine = permguard_host::operations::mutation::Mutations::open(
        &volume,
        projection,
        std::sync::Arc::new(permguard_host::time::TimeGuard::system(
            std::time::Duration::from_secs(30),
        )),
    )
    .unwrap_or_else(|error| unreachable!("a test mutation transaction opens: {error}"));
    permguard_host::composition::MutationHandle::new(
        std::sync::Arc::new(engine),
        crate::catalog::CATALOG_DOMAIN,
    )
}

/// A mutation transaction of the ref updates over an offline engine of its own on a fresh volume
/// under `directory`, for a test.
#[cfg(test)]
pub(crate) fn ref_mutations_for_tests(
    directory: &std::path::Path,
) -> permguard_host::composition::MutationHandle {
    crate::store::testing::offline_ref_mutations(directory)
        .unwrap_or_else(|error| unreachable!("a test mutation transaction opens: {error}"))
}

/// The audit handle, when an audit recorder is composed.
pub(crate) fn audit(context: &PlaneContext<'_>) -> Option<Audit> {
    registration(context)?
        .audit::<ControlPlaneAudit>()
        .ok()
        .flatten()
}

/// The head statement signer, when the plane's signing ring is composed: typed, it signs head
/// statements and nothing else (WP-3.2).
pub(crate) fn head_signer(context: &PlaneContext<'_>) -> Option<Signer<HeadStatementV1>> {
    registration(context)?
        .signer::<HeadStatementV1>()
        .ok()
        .flatten()
}

/// The export manifest signer, when the Host composes `host.operations` for this plane (WP-7.10).
pub(crate) fn export_signer(context: &PlaneContext<'_>) -> Option<Signer<LedgerExportV1>> {
    registration(context)?
        .signer::<LedgerExportV1>()
        .ok()
        .flatten()
}

/// The `events.import` checkpoint signer, when the plane's signing ring is composed (WP-6.2c1).
pub(crate) fn import_signer(context: &PlaneContext<'_>) -> Option<Signer<ImportCheckpointV1>> {
    registration(context)?
        .signer::<ImportCheckpointV1>()
        .ok()
        .flatten()
}

/// A ring a test holds itself.
#[cfg(test)]
pub(crate) type TestRing = Arc<dyn permguard_core::KeyManager>;

/// A test's ring that keeps no epoch, given one: epoch 1, the set digest over its published
/// keys. A head statement binds a ring's epoch and set (WP-7.1), and a ring that names none
/// cannot sign one.
#[cfg(test)]
struct EpochOne(TestRing);

#[cfg(test)]
impl permguard_core::keys::Sign for EpochOne {
    fn active_key_id(&self) -> permguard_core::keys::Result<permguard_core::KeyId> {
        self.0.active_key_id()
    }
    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<permguard_core::Signature> {
        self.0.sign(payload)
    }
}

#[cfg(test)]
impl PublicSet for EpochOne {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<permguard_core::Jwk>> {
        self.0.public_keys()
    }
    fn key_set(&self) -> permguard_core::keys::Result<permguard_core::keys::KeySetView> {
        let keys = self.0.public_keys()?;
        let published = serde_json::to_vec(&permguard_core::JwkSet::new(keys))
            .map_err(|error| permguard_core::KeyError::backend(error.to_string()))?;
        Ok(permguard_core::keys::KeySetView {
            epoch: 1,
            digest: *permguard_objects::Digest::compute(&published).raw(),
            algorithm: "EdDSA",
        })
    }
}

#[cfg(test)]
impl permguard_core::KeyManager for EpochOne {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn maintain(&self) -> permguard_core::keys::Result<permguard_core::Maintenance> {
        self.0.maintain()
    }
}

/// A head statement signer over `keys`, for a test that holds a ring of its own.
#[cfg(test)]
pub(crate) fn head_signer_for_tests(keys: TestRing) -> Signer<HeadStatementV1> {
    let keys: TestRing = Arc::new(EpochOne(keys));
    permguard_host::composition::Host::builder()
        .ring(permguard_host::composition::CONTROL_ATTEST, keys)
        .build()
        .register(Declaration::new(PLANE).signs::<HeadStatementV1>())
        .ok()
        .and_then(|registration| registration.signer::<HeadStatementV1>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared signer over a composed ring"))
}

/// A ring on disk under `root`, published and active, for a test that signs with it.
#[cfg(test)]
pub(crate) fn ring_for_tests(root: &std::path::Path) -> TestRing {
    use permguard_core::keys::KeyManager as _;

    let keys = Arc::new(permguard_std::keys::DirectoryKeyManager::new(
        root.join("keys"),
        permguard_std::keys::KeyPolicy {
            publish_ahead: std::time::Duration::ZERO,
            rotate_every: std::time::Duration::from_secs(3600),
            retain: std::time::Duration::from_secs(3600),
            verify_retain: std::time::Duration::from_secs(3600),
        },
    ));
    keys.maintain()
        .unwrap_or_else(|error| unreachable!("the ring publishes: {error}"));
    keys.maintain()
        .unwrap_or_else(|error| unreachable!("the ring activates: {error}"));
    keys
}

/// An export manifest signer over `keys`, composed as the Host's `host.operations`, for a test
/// that holds a ring of its own (WP-7.10).
#[cfg(test)]
pub(crate) fn export_signer_for_tests(keys: TestRing) -> Signer<LedgerExportV1> {
    let keys: TestRing = Arc::new(EpochOne(keys));
    permguard_host::composition::Host::builder()
        .ring(permguard_host::composition::HOST_OPERATIONS, keys)
        .build()
        .register(Declaration::new(PLANE).signs::<LedgerExportV1>())
        .ok()
        .and_then(|registration| registration.signer::<LedgerExportV1>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared signer over a composed ring"))
}

/// An `events.import` checkpoint signer over `keys`, for a test that holds a ring of its own.
#[cfg(test)]
pub(crate) fn import_signer_for_tests(keys: TestRing) -> Signer<ImportCheckpointV1> {
    let keys: TestRing = Arc::new(EpochOne(keys));
    permguard_host::composition::Host::builder()
        .ring(permguard_host::composition::CONTROL_ATTEST, keys)
        .build()
        .register(Declaration::new(PLANE).signs::<ImportCheckpointV1>())
        .ok()
        .and_then(|registration| registration.signer::<ImportCheckpointV1>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared signer over a composed ring"))
}

/// This plane's own public set, to publish, when its signing ring is composed.
pub(crate) fn own_public_keys(context: &PlaneContext<'_>) -> Option<Arc<dyn PublicSet>> {
    let signer = registration(context)?
        .signer::<HeadStatementV1>()
        .ok()
        .flatten()?;
    Some(Arc::new(signer))
}

/// The data plane's public set, to verify a local producer with, when that ring is composed.
pub(crate) fn data_public_keys(context: &PlaneContext<'_>) -> Option<Arc<dyn PublicSet>> {
    let keys = registration(context)?
        .public_keys(DATA_ATTEST)
        .ok()
        .flatten()?;
    Some(Arc::new(keys))
}

/// An audit handle over `recorder`, for a test that needs one without composing a server.
#[cfg(test)]
pub(crate) fn audit_for_tests(recorder: permguard_core::AuditRecorder) -> Audit {
    permguard_host::composition::Host::builder()
        .audit(recorder)
        .build()
        .register(declaration())
        .ok()
        .and_then(|registration| registration.audit::<ControlPlaneAudit>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared schema with a composed recorder"))
}

#[cfg(test)]
mod tests {
    use permguard_host::audit::{CONTROL, REGISTRY};
    use permguard_host::composition::AuditSchema as _;

    use super::ControlPlaneAudit;

    /// The Host refuses an action its registry does not name, which would fail the Plane's call.
    #[test]
    fn every_action_of_the_schema_is_registered_with_the_host_under_this_plane() {
        for action in ControlPlaneAudit::ACTIONS {
            let schema = REGISTRY
                .iter()
                .find(|schema| schema.action == *action)
                .unwrap_or_else(|| panic!("`{action}` is not registered with the Host"));
            assert_eq!(schema.root, CONTROL, "{action}");
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
        let declaration = super::declaration();
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
                (TaskType::PolicyMirror, ContractRole::Provider),
                (TaskType::EventsImport, ContractRole::Provider),
                (TaskType::DecisionsShip, ContractRole::Consumer),
                (TaskType::EventsShip, ContractRole::Consumer),
            ]
        );
    }
}
