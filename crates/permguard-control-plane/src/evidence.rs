// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `evidence.read` gate (WP-6.3c, owner decisions of 2026-10-20).
//!
//! `1-control-plane.md` grants decision and event evidence reads as `evidence.read` on the exact
//! resource: the ledger in this plane's tree, `plane/control/zone/{zone_id}/ledger/{ledger_id}`,
//! the resource `catalog.read` takes, by the ids the scope resolves to. The checks run in the
//! catalog's order (WP-2.4), so authorization precedes any lookup that could say whether another
//! tenant's ledger exists:
//!
//! | Step                  | Check                                    | Refused as                     |
//! | --------------------- | ---------------------------------------- | ------------------------------ |
//! | before any lookup     | anything granted under the plane         | `401` or `403`, the denial     |
//! | the scope is unknown  | a grant covering the whole plane         | the same denial as a foreign   |
//! |                       |                                          | ledger; `not_found` otherwise  |
//! | the scope is resolved | the ledger exactly, or the whole plane   | `403`                          |
//! |                       | for a legacy stream mixing tenants       |                                |
//!
//! The signers, the discovery documents and the legacy ingest are not evidence reads and stay as
//! they are.

use permguard_core::AccessDenial;
use permguard_core::authz::{Actor, Resource, operations};
use permguard_host::composition::Authorization;

/// What a gated read is refused with: an access denial, in its closed body, or the read's own
/// refusal.
#[derive(Debug)]
pub(crate) enum Gated<E> {
    Denied(AccessDenial),
    Refused(E),
}

/// The plane's resource, what nothing-granted is checked under.
pub(crate) fn plane() -> Resource {
    crate::catalog::plane_resource()
}

/// Refuses a caller granted nothing for `evidence.read` under the plane, before any lookup.
pub(crate) fn admitted(authorization: &Authorization, actor: &Actor) -> Result<(), AccessDenial> {
    authorization.may_act_under(actor, operations::EVIDENCE_READ, &plane())
}

/// What a scope that resolved to nothing is answered with: `Ok(())`, that is its own `not_found`,
/// only to a caller whose grants cover the whole plane; the denial a foreign ledger gets to anyone
/// else.
pub(crate) fn unknown(authorization: &Authorization, actor: &Actor) -> Result<(), AccessDenial> {
    authorization.not_found_or_forbidden(actor, operations::EVIDENCE_READ, &plane())
}

/// Authorizes a read of the ledger `zone_id`/`ledger_id`, exactly.
pub(crate) fn on_ledger(
    authorization: &Authorization,
    actor: &Actor,
    zone_id: &str,
    ledger_id: &str,
) -> Result<(), AccessDenial> {
    authorization.authorize(
        actor,
        operations::EVIDENCE_READ,
        &crate::catalog::ledger_resource(zone_id, ledger_id),
    )
}

/// Authorizes a read only a grant covering the whole plane may make: a legacy decision stream,
/// which mixes every tenant's records. A grant on the plane's own node alone is not one (after
/// the review).
pub(crate) fn on_plane(authorization: &Authorization, actor: &Actor) -> Result<(), AccessDenial> {
    authorization.not_found_or_forbidden(actor, operations::EVIDENCE_READ, &plane())
}

/// Every operation public, for a test about something other than authorization.
#[cfg(test)]
pub(crate) fn permissive() -> std::sync::Arc<Authorization> {
    std::sync::Arc::new(Authorization::permissive())
}

/// A catalog no gate may consult before it admitted the caller: every lookup panics (after the
/// review).
#[cfg(test)]
pub(crate) struct Untouchable;

#[cfg(test)]
impl permguard_core::catalog::Catalog for Untouchable {
    fn name(&self) -> &'static str {
        "untouchable"
    }

    fn create_zone(
        &self,
        _: &str,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn list_zones(
        &self,
    ) -> Result<Vec<permguard_core::catalog::Zone>, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn get_zone(
        &self,
        _: &permguard_core::catalog::Selector,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn rename_zone(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &str,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn delete_zone(
        &self,
        _: &permguard_core::catalog::Selector,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn create_ledger(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &str,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn list_ledgers(
        &self,
        _: &permguard_core::catalog::Selector,
    ) -> Result<Vec<permguard_core::catalog::Ledger>, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn get_ledger(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Selector,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn rename_ledger(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Selector,
        _: &str,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn delete_ledger(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Selector,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::authz::{ActorContext, Credential, Principal, Selector};
    use permguard_host::authz::PublicGrant;

    use super::*;

    fn actor() -> Actor {
        Actor::Authenticated(ActorContext::new(
            Principal::new("spiffe://acme/auditor").expect("a principal"),
            Credential::SanUri,
            None,
        ))
    }

    /// Everybody granted `evidence.read` on `selector`, and nothing else.
    fn granted(selector: &str) -> Authorization {
        Authorization::public_only(&[PublicGrant::new(
            &[operations::EVIDENCE_READ],
            Selector::parse(selector).expect("a selector"),
        )])
    }

    /// WP-6.3c: nothing granted under the plane is refused before any lookup, `401` for nobody and
    /// `403` for somebody; another operation's grant admits nothing.
    #[test]
    fn nothing_granted_under_the_plane_is_refused_before_any_lookup() {
        let closed = Authorization::closed();
        assert_eq!(
            admitted(&closed, &Actor::Anonymous)
                .expect_err("closed")
                .http_status(),
            401
        );
        assert_eq!(
            admitted(&closed, &actor())
                .expect_err("closed")
                .http_status(),
            403
        );
        let catalog_only = Authorization::public_only(&[PublicGrant::new(
            &[operations::CATALOG_READ],
            Selector::parse("plane/control/*").expect("a selector"),
        )]);
        assert!(admitted(&catalog_only, &actor()).is_err());
        // On the Data Plane's tree, not this one's (owner decision of 2026-10-20).
        assert!(admitted(&granted("plane/data/*"), &actor()).is_err());
    }

    /// WP-6.3c, owner decision of 2026-10-20: a ledger grant reads that ledger exactly, nothing else
    /// and no legacy stream; an unknown scope answers the same denial as a foreign ledger.
    #[test]
    fn a_ledger_grant_reads_its_ledger_and_nothing_else() {
        let ledger = granted("plane/control/zone/z1/ledger/l1");
        assert!(
            admitted(&ledger, &actor()).is_ok(),
            "something under the plane"
        );
        assert!(on_ledger(&ledger, &actor(), "z1", "l1").is_ok());
        assert!(on_ledger(&ledger, &actor(), "z1", "l2").is_err());
        assert!(on_ledger(&ledger, &actor(), "z2", "l1").is_err());
        assert!(on_plane(&ledger, &actor()).is_err(), "a legacy stream");
        // The plane's own node alone covers no ledger and no legacy stream (after the review).
        let node = granted("plane/control");
        assert!(on_plane(&node, &actor()).is_err());
        assert!(unknown(&node, &actor()).is_err());
        assert_eq!(
            unknown(&ledger, &actor())
                .expect_err("indistinguishable from a foreign ledger")
                .http_status(),
            on_ledger(&ledger, &actor(), "z1", "l2")
                .expect_err("foreign")
                .http_status()
        );
    }

    /// WP-6.3c: a grant covering the whole plane reads every ledger and every legacy stream, and is
    /// told a scope it names does not exist.
    #[test]
    fn a_whole_plane_grant_reads_everything_and_learns_what_does_not_exist() {
        let plane = granted("plane/control/*");
        assert!(admitted(&plane, &actor()).is_ok());
        assert!(on_ledger(&plane, &actor(), "z9", "l9").is_ok());
        assert!(on_plane(&plane, &actor()).is_ok());
        assert!(unknown(&plane, &actor()).is_ok(), "its own not_found");
    }
}
