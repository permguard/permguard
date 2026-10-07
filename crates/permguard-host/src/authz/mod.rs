// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's authorization (WP-2.4): the grant store on the volume, the credential mapper that
//! produces an actor, and the handle a Plane authorizes through.
//!
//! The model itself — resources, selectors, principals, allows — is `permguard_core::authz`, so
//! every crate reads a selector the same way. This module owns what touches the volume and the
//! configuration: [`store::GrantStore`] over `host/authz/`, [`mapper::PrincipalMapper`] behind
//! the transport, [`oidc::Verifier`] for a pinned issuer, and [`Authorization`], built by the
//! composition root and handed to each Plane with its registration.
//!
//! `authorize` runs before any resource lookup (P8). A route that accepts a name as well as an
//! id asks in two stages (owner decision, 2026-10-06): [`Authorization::may_act_under`] refuses a
//! caller with nothing under the Plane before anything is resolved; [`Authorization::authorize`]
//! decides on the exact resource once the id is known; and a name that resolves to nothing is
//! answered as [`Authorization::not_found_or_forbidden`] says — not found only for a caller whose
//! grants cover the whole Plane, the same refusal as out of scope for everybody else.

pub mod mapper;
pub mod oidc;
pub mod record;
pub mod store;

use std::sync::Arc;

use permguard_core::AccessDenial;
use permguard_core::authz::{Actor, Allow, AllowSet, Principal, Resource, Selector};

pub use mapper::{MapperError, PrincipalMapper, Rule};
pub use oidc::OidcRule;
pub use record::{GrantId, GrantRecord, Status};
pub use store::{AuthzError, Bootstrap, Change, GrantStore, Issue};

/// One `host.authz.public[]` entry: what anybody may do, declared in the configuration and
/// never journaled (owner decision, 2026-10-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicGrant {
    pub operations: Vec<String>,
    pub selector: Selector,
    pub resource_types: Vec<String>,
}

impl PublicGrant {
    /// A public grant of `operations` on `selector`, every resource type.
    pub fn new(operations: &[&str], selector: Selector) -> Self {
        Self {
            operations: operations
                .iter()
                .map(|operation| (*operation).to_owned())
                .collect(),
            selector,
            resource_types: vec![permguard_core::authz::resource_types::ANY.to_owned()],
        }
    }

    fn allows(&self) -> Vec<Allow> {
        let mut allows = Vec::new();
        for operation in &self.operations {
            for resource_type in &self.resource_types {
                allows.push(Allow {
                    principal: Principal::anonymous(),
                    operation: operation.clone(),
                    selector: self.selector.clone(),
                    resource_type: resource_type.clone(),
                });
            }
        }
        allows
    }
}

/// Authorizes a request against the Host's grants: the handle every registered Plane receives.
///
/// Public grants are held for the reserved `anonymous` principal and consulted for every actor
/// with a principal: what is public is public to an authenticated caller too. A credential no
/// rule maps is unauthenticated whatever is public.
pub struct Authorization {
    store: Option<Arc<GrantStore>>,
    public: AllowSet,
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization")
            .field("store", &self.store.is_some())
            .field("public", &self.public.allows().len())
            .finish()
    }
}

impl Authorization {
    /// The grants of `store`, plus what the configuration declares public.
    pub fn new(store: Arc<GrantStore>, public: &[PublicGrant]) -> Self {
        Self {
            store: Some(store),
            public: public_allows(public),
        }
    }

    /// Public grants only, no store: what a test, or a composition without a volume, uses.
    pub fn public_only(public: &[PublicGrant]) -> Self {
        Self {
            store: None,
            public: public_allows(public),
        }
    }

    /// Everything closed: no store, nothing public. The fail-closed default of a composition
    /// that built no authorization.
    pub fn closed() -> Self {
        Self::public_only(&[])
    }

    /// Every registered operation public on the Host and both Planes: what a test that is about
    /// something other than authorization composes with, and nothing a deployment should.
    pub fn permissive() -> Self {
        use permguard_core::authz::{Resource, operations};

        let everything =
            |resource: Resource| PublicGrant::new(operations::ALL, Selector::under(resource));
        Self::public_only(&[
            everything(Resource::host()),
            everything(Resource::plane("control")),
            everything(Resource::plane("data")),
        ])
    }

    /// The grant-store revision the next decision reads at; `0` without a store.
    pub fn revision(&self) -> u64 {
        self.store.as_ref().map_or(0, |store| store.revision())
    }

    fn allows(&self) -> AllowSet {
        let now = store::now();
        let mut allows = self
            .store
            .as_ref()
            .map_or_else(AllowSet::default, |store| store.allows_at(now));
        allows.extend(&self.public);
        allows
    }

    /// Whether `actor` may do `operation` on exactly `resource`: deny by default.
    pub fn authorize(
        &self,
        actor: &Actor,
        operation: &str,
        resource: &Resource,
    ) -> Result<(), AccessDenial> {
        let principal = actor.principal()?;
        let allows = self.allows();
        if allows.permits(&principal, operation, resource)
            || allows.permits(&Principal::anonymous(), operation, resource)
        {
            return Ok(());
        }
        Err(actor.without_grant())
    }

    /// The first stage of a lookup by name: whether `actor` holds anything for `operation` at or
    /// under `scope`. A caller with nothing there is refused before any resource is resolved.
    pub fn may_act_under(
        &self,
        actor: &Actor,
        operation: &str,
        scope: &Resource,
    ) -> Result<(), AccessDenial> {
        let principal = actor.principal()?;
        let allows = self.allows();
        if allows.permits_anywhere_under(&principal, operation, scope)
            || allows.permits_anywhere_under(&Principal::anonymous(), operation, scope)
        {
            return Ok(());
        }
        Err(actor.without_grant())
    }

    /// Whether `actor` may do `operation` on everything under `scope`, so a name that resolves to
    /// nothing may honestly be answered as not found.
    pub fn covers_whole(&self, actor: &Actor, operation: &str, scope: &Resource) -> bool {
        let Ok(principal) = actor.principal() else {
            return false;
        };
        let allows = self.allows();
        allows.permits_whole(&principal, operation, scope)
            || allows.permits_whole(&Principal::anonymous(), operation, scope)
    }

    /// What a name that resolved to nothing is answered with: `Ok(())` to say not found, when
    /// the caller's grants cover the whole `scope`; otherwise the same denial as out of scope,
    /// so an unknown name and a foreign name are indistinguishable.
    pub fn not_found_or_forbidden(
        &self,
        actor: &Actor,
        operation: &str,
        scope: &Resource,
    ) -> Result<(), AccessDenial> {
        if self.covers_whole(actor, operation, scope) {
            Ok(())
        } else {
            Err(actor.without_grant())
        }
    }
}

fn public_allows(public: &[PublicGrant]) -> AllowSet {
    AllowSet::new(public.iter().flat_map(PublicGrant::allows).collect(), 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::authz::{ActorContext, Credential, operations};

    fn actor(principal: &str) -> Actor {
        Actor::Authenticated(ActorContext::new(
            Principal::new(principal).expect("a principal"),
            Credential::SanUri,
            None,
        ))
    }

    #[test]
    fn closed_refuses_everybody_and_public_admits_anonymous_and_authenticated_alike() {
        let closed = Authorization::closed();
        let zone = Resource::zone("control", "z1");
        assert_eq!(
            closed
                .authorize(&Actor::Anonymous, operations::CATALOG_READ, &zone)
                .expect_err("closed")
                .http_status(),
            401
        );
        assert_eq!(
            closed
                .authorize(&actor("spiffe://acme/x"), operations::CATALOG_READ, &zone)
                .expect_err("closed")
                .http_status(),
            403
        );
        let public = Authorization::public_only(&[PublicGrant::new(
            &[operations::CATALOG_READ],
            Selector::parse("plane/control/*").expect("a selector"),
        )]);
        assert!(
            public
                .authorize(&Actor::Anonymous, operations::CATALOG_READ, &zone)
                .is_ok()
        );
        assert!(
            public
                .authorize(&actor("spiffe://acme/x"), operations::CATALOG_READ, &zone)
                .is_ok(),
            "what is public is public to everybody with a principal"
        );
        assert_eq!(
            public
                .authorize(&Actor::Anonymous, operations::CATALOG_WRITE, &zone)
                .expect_err("not public")
                .http_status(),
            401
        );
        let unmapped = Actor::Unmapped {
            reason: "stranger".to_owned(),
        };
        assert_eq!(
            public
                .authorize(&unmapped, operations::CATALOG_READ, &zone)
                .expect_err("a stranger's certificate never widens to the public grants")
                .http_status(),
            401
        );
        assert!(
            public
                .may_act_under(
                    &Actor::Anonymous,
                    operations::CATALOG_READ,
                    &Resource::plane("control")
                )
                .is_ok()
        );
        assert!(public.covers_whole(
            &Actor::Anonymous,
            operations::CATALOG_READ,
            &Resource::plane("control")
        ));
        assert!(!public.covers_whole(
            &Actor::Anonymous,
            operations::CATALOG_READ,
            &Resource::plane("data")
        ));
    }
}
