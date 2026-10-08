// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane declares to the Host, and the handles it gets back (WP-2.1, P1).
//!
//! | Declared                          | Handle                          | Used by                          |
//! | --------------------------------- | ------------------------------- | -------------------------------- |
//! | signs `HeadStatementV1`           | `Signer<HeadStatementV1>`       | NOTP head statements, the JWKS   |
//! | reads the public set of `data.attest` | `PublicKeys`                | verifying a local producer       |
//! | audit schema [`ControlPlaneAudit`] | `AuditHandle<ControlPlaneAudit>` | catalog, NOTP, GC                |
//!
//! The plane never sees a key manager, the audit recorder or the secret store: only these.

use std::sync::Arc;

use permguard_core::PlaneContext;
use permguard_core::keys::{PublicSet, SigningRing};
use permguard_host::composition::{
    AuditHandle, AuditSchema, DATA_ATTEST, Declaration, HeadStatementV1, Registration,
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
        "ledger.pushed",
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
    Declaration::new(PLANE)
        .signs::<HeadStatementV1>()
        .reads_public_keys(DATA_ATTEST)
        .audits::<ControlPlaneAudit>()
}

fn registration(context: &PlaneContext<'_>) -> Option<Arc<Registration>> {
    context.handles::<Registration>()
}

/// This Host's `host_id`, the salt of the cursor keys this plane derives from its stores' roots
/// (WP-3.3); `None` when no Host registered the plane.
pub(crate) fn host_id(context: &PlaneContext<'_>) -> Option<[u8; 16]> {
    registration(context)?.host_id()
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
        .audit::<ControlPlaneAudit>()
        .ok()
        .flatten()
}

/// The head statement signer, when the plane's signing ring is composed.
pub(crate) fn head_signer(context: &PlaneContext<'_>) -> Option<Arc<dyn SigningRing>> {
    let signer = registration(context)?
        .signer::<HeadStatementV1>()
        .ok()
        .flatten()?;
    Some(Arc::new(signer))
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
