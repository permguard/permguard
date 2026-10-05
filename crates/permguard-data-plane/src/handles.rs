// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane declares to the Host, and the handles it gets back (WP-2.1, P1).
//!
//! | Declared                              | Handle                           | Used by                        |
//! | ------------------------------------- | -------------------------------- | ------------------------------ |
//! | signs `DecisionBatchV1`               | `Signer<DecisionBatchV1>`        | the decision shipper, the JWKS |
//! | signs `EventBatchV1`                  | `Signer<EventBatchV1>`           | the event shipper              |
//! | audit schema [`DataPlaneAudit`]       | `AuditHandle<DataPlaneAudit>`    | decisions, mirrors             |
//! | the [`DecisionCommitment`] secret     | `SecretHandle<DecisionCommitment>` | input commitments            |
//!
//! The plane never sees a key manager, the audit recorder, the secret store or a secret's bytes:
//! only these.

use std::sync::Arc;

use permguard_core::keys::{PublicSet, SigningRing};
use permguard_core::{Config, ServerContext};
use permguard_host::composition::{
    AuditHandle, AuditSchema, DecisionBatchV1, Declaration, EventBatchV1, Registration,
    SecretHandle, SecretPurpose,
};

use crate::service::PLANE;

/// Every action this plane records to the audit trail.
pub struct DataPlaneAudit;

impl AuditSchema for DataPlaneAudit {
    const NAME: &'static str = "data-plane.v1";
    const ACTIONS: &'static [&'static str] = &["authz.decision", "ledger.synchronized"];
}

/// The key decision input commitments are taken under.
pub struct DecisionCommitment;

impl SecretPurpose for DecisionCommitment {
    const NAME: &'static str = "decision.commitment";
    /// The same floor the pseudonym key has: below it, an exhaustive search over the key is cheaper
    /// than a dictionary over the values.
    const MIN_BYTES: usize = 32;
}

/// This plane's audit handle.
pub type Audit = AuditHandle<DataPlaneAudit>;

/// What this plane declares to the Host under `config`: the commitment key only when the decision
/// log is on and names one, so a plane that keeps no log resolves no secret.
pub(crate) fn declaration(config: &Config) -> Declaration {
    let declaration = Declaration::new(PLANE)
        .signs::<DecisionBatchV1>()
        .signs::<EventBatchV1>()
        .audits::<DataPlaneAudit>();
    match config.log_commitment_key_ref() {
        Some(reference) if config.log_enabled() => declaration.uses_secret::<DecisionCommitment>(
            reference.clone(),
            config.log_commitment_key_version(),
        ),
        _ => declaration,
    }
}

fn registration(context: &ServerContext<'_>) -> Option<Arc<Registration>> {
    context.plane_handles::<Registration>(PLANE)
}

/// The audit handle, when an audit recorder is composed.
pub(crate) fn audit(context: &ServerContext<'_>) -> Option<Audit> {
    registration(context)?
        .audit::<DataPlaneAudit>()
        .ok()
        .flatten()
}

/// The decision batch signer, when the plane's signing ring is composed.
pub(crate) fn decision_signer(context: &ServerContext<'_>) -> Option<Arc<dyn SigningRing>> {
    let signer = registration(context)?
        .signer::<DecisionBatchV1>()
        .ok()
        .flatten()?;
    Some(Arc::new(signer))
}

/// The event batch signer, when the plane's signing ring is composed.
pub(crate) fn event_signer(context: &ServerContext<'_>) -> Option<Arc<dyn SigningRing>> {
    let signer = registration(context)?
        .signer::<EventBatchV1>()
        .ok()
        .flatten()?;
    Some(Arc::new(signer))
}

/// This plane's public set, to publish, when its signing ring is composed.
pub(crate) fn public_keys(context: &ServerContext<'_>) -> Option<Arc<dyn PublicSet>> {
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
        .register(Declaration::new(PLANE).audits::<DataPlaneAudit>(), None)
        .ok()
        .and_then(|registration| registration.audit::<DataPlaneAudit>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared schema with a composed recorder"))
}

/// The commitment key's handle, when the declaration named one.
pub(crate) fn commitment(context: &ServerContext<'_>) -> Option<SecretHandle<DecisionCommitment>> {
    registration(context)?.secret::<DecisionCommitment>().ok()
}
