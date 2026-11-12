// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's authorization (`2-security/8` Authorization): the access tokens of the Authority
//! Plane, verified on the Host, the public grants of the configuration, and the handle a Plane
//! authorizes through.
//!
//! The model itself — resources, selectors, principals, scopes — is `permguard_core::authz`, so
//! every crate reads a selector the same way. This module owns what touches the volume and the
//! configuration: [`access_tokens`] and [`authority::AuthorityTrust`], what a bearer is verified
//! with; [`mapper::PrincipalMapper`], the bootstrap certificate; [`store::BootstrapStore`] over
//! `host/authz/`; and [`Authorization`], built by the composition root and handed to each Plane
//! with its registration.
//!
//! `authorize` runs before any resource lookup (P8). A route that accepts a name as well as an
//! id asks in two stages (owner decision, 2026-10-06): [`Authorization::may_act_under`] refuses a
//! caller with nothing under the Plane before anything is resolved; [`Authorization::authorize`]
//! decides on the exact resource once the id is known; and a name that resolves to nothing is
//! answered as [`Authorization::not_found_or_forbidden`] says — not found only for a caller whose
//! scopes cover the whole Plane, the same refusal as out of scope for everybody else.

pub mod access_tokens;
pub mod authority;
pub mod bootstrap;
pub mod mapper;
pub mod status_lists;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

use permguard_core::AccessDenial;
use permguard_core::authz::{
    Actor, Allow, AllowSet, Principal, Resource, Selector, TokenGrant, per_host_reach,
};

pub use authority::AuthorityTrust;
pub use mapper::{MapperError, PrincipalMapper};
pub use store::{AuthzError, Bootstrap, BootstrapStore};

/// One `host.authz.public[]` entry: what anybody may do without a token, declared in the
/// configuration and never journaled (owner decision, 2026-10-06).
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

/// Authorizes a request: the handle every registered Plane receives.
///
/// An access token's bearer acts within its token's scopes alone: public grants never widen it.
/// The bootstrap principal holds the per-Host operations on its own Host ([`per_host_reach`]).
/// Every other caller acts within the public grants, the reserved `anonymous` principal's; a
/// certificate that maps to nothing is unauthenticated whatever is public.
pub struct Authorization {
    public: AllowSet,
    /// The Host's bootstrap principal, `cert:sha256:<hex>`: the only principal that is not a
    /// token's, for break-glass on its own Host.
    bootstrap: Option<Principal>,
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization")
            .field("public", &self.public.allows().len())
            .field("bootstrap", &self.bootstrap.is_some())
            .finish()
    }
}

impl Authorization {
    /// What the configuration declares public, and nothing else.
    pub fn public_only(public: &[PublicGrant]) -> Self {
        Self {
            public: AllowSet::new(public.iter().flat_map(PublicGrant::allows).collect(), 0),
            bootstrap: None,
        }
    }

    /// Everything closed: nothing public, tokens alone. The fail-closed default of a composition
    /// that built no authorization.
    pub fn closed() -> Self {
        Self::public_only(&[])
    }

    /// Every registered operation public on the Host and every Plane: what a test that is about
    /// something other than authorization composes with, and nothing a deployment should.
    pub fn permissive() -> Self {
        use permguard_core::authz::operations;

        let everything =
            |resource: Resource| PublicGrant::new(operations::ALL, Selector::under(resource));
        Self::public_only(&[
            everything(Resource::host()),
            everything(Resource::plane("authority")),
            everything(Resource::plane("control")),
            everything(Resource::plane("data")),
        ])
    }

    /// The Host's bootstrap principal: it holds the per-Host operations on its own Host and
    /// Planes ([`per_host_reach`]), presented by its certificate and nothing else.
    pub fn with_bootstrap(mut self, principal: Option<Principal>) -> Self {
        self.bootstrap = principal;
        self
    }

    /// The token's verdict for `actor`, when it bears one: refused when the token does not allow
    /// it, `Some(subject)` when it does, `None` for a caller without a token.
    fn token_decides(
        actor: &Actor,
        operation: &str,
        allowed: impl Fn(&TokenGrant) -> bool,
    ) -> Result<Option<Principal>, AccessDenial> {
        let Actor::Authenticated(context) = actor else {
            return Ok(None);
        };
        let Some(grant) = context.token() else {
            return Ok(None);
        };
        if !allowed(grant) {
            return Err(actor.without_grant_for(operation));
        }
        Ok(Some(context.authorization_principal().clone()))
    }

    /// The bootstrap principal's standing, when `actor` is it and `reach` holds.
    fn bootstrap_reaches(&self, actor: &Actor, reach: impl Fn() -> bool) -> Option<Principal> {
        let Actor::Authenticated(context) = actor else {
            return None;
        };
        let principal = context.authorization_principal();
        // The offline certificate itself, as the mapper names it: never a principal another
        // credential could come to carry.
        (context.token().is_none()
            && context.credential() == permguard_core::authz::Credential::Certificate
            && self.bootstrap.as_ref() == Some(principal)
            && reach())
        .then(|| principal.clone())
    }

    /// Whether `actor` may do `operation` on exactly `resource`: deny by default.
    pub fn authorize(
        &self,
        actor: &Actor,
        operation: &str,
        resource: &Resource,
    ) -> Result<(), AccessDenial> {
        self.authorize_by(actor, operation, resource).map(|_| ())
    }

    /// [`Authorization::authorize`], answering whose standing allowed it: the token's subject, the
    /// bootstrap principal, or `anonymous` for a public grant. What the audit names.
    pub fn authorize_by(
        &self,
        actor: &Actor,
        operation: &str,
        resource: &Resource,
    ) -> Result<Principal, AccessDenial> {
        actor.principal()?;
        if let Some(decided) =
            Self::token_decides(actor, operation, |grant| grant.permits(operation, resource))?
        {
            return Ok(decided);
        }
        if let Some(bootstrap) =
            self.bootstrap_reaches(actor, || per_host_reach(operation, resource))
        {
            return Ok(bootstrap);
        }
        let anonymous = Principal::anonymous();
        if self.public.permits(&anonymous, operation, resource) {
            return Ok(anonymous);
        }
        Err(actor.without_grant_for(operation))
    }

    /// The first stage of a lookup by name: whether `actor` holds anything for `operation` at or
    /// under `scope`. A caller with nothing there is refused before any resource is resolved.
    pub fn may_act_under(
        &self,
        actor: &Actor,
        operation: &str,
        scope: &Resource,
    ) -> Result<(), AccessDenial> {
        actor.principal()?;
        if Self::token_decides(actor, operation, |grant| {
            grant.permits_anywhere_under(operation, scope)
        })?
        .is_some()
            || self
                .bootstrap_reaches(actor, || per_host_reach(operation, scope))
                .is_some()
            || self
                .public
                .permits_anywhere_under(&Principal::anonymous(), operation, scope)
        {
            return Ok(());
        }
        Err(actor.without_grant_for(operation))
    }

    /// Whether `actor` may do `operation` on everything under `scope`, so a name that resolves to
    /// nothing may honestly be answered as not found.
    pub fn covers_whole(&self, actor: &Actor, operation: &str, scope: &Resource) -> bool {
        if actor.principal().is_err() {
            return false;
        }
        match Self::token_decides(actor, operation, |grant| {
            grant.permits_whole(operation, scope)
        }) {
            Err(_) => return false,
            Ok(Some(_)) => return true,
            Ok(None) => {}
        }
        self.bootstrap_reaches(actor, || per_host_reach(operation, scope))
            .is_some()
            || self
                .public
                .permits_whole(&Principal::anonymous(), operation, scope)
    }

    /// What a name that resolved to nothing is answered with: `Ok(())` to say not found, when
    /// the caller covers the whole `scope`; otherwise the same denial as out of scope, so an
    /// unknown name and a foreign name are indistinguishable.
    pub fn not_found_or_forbidden(
        &self,
        actor: &Actor,
        operation: &str,
        scope: &Resource,
    ) -> Result<(), AccessDenial> {
        if self.covers_whole(actor, operation, scope) {
            Ok(())
        } else {
            Err(actor.without_grant_for(operation))
        }
    }
}

impl permguard_core::authz::Admission for Authorization {
    fn may_act_under(
        &self,
        actor: &Actor,
        operation: &str,
        scope: &Resource,
    ) -> Result<(), AccessDenial> {
        Self::may_act_under(self, actor, operation, scope)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::authz::{ActorContext, Credential, TokenScope, operations};

    fn actor(principal: &str) -> Actor {
        Actor::Authenticated(ActorContext::new(
            Principal::new(principal).expect("a principal"),
            Credential::Certificate,
            None,
        ))
    }

    fn token(operations: &[&str], selector: &str) -> Actor {
        Actor::Authenticated(ActorContext::of_token(
            Principal::new("sa:billing").expect("a principal"),
            TokenGrant {
                scopes: vec![TokenScope {
                    operations: operations.iter().map(|op| (*op).to_owned()).collect(),
                    selector: Selector::parse(selector).expect("a selector"),
                }],
                jti: "j".to_owned(),
                list_uri: "u".to_owned(),
                list_iat: 1,
                list_digest: [0; 32],
            },
        ))
    }

    /// `2-security/8` Authorization: a token decides alone, within its scopes, and a public grant
    /// never widens it.
    #[test]
    fn a_token_decides_alone_and_a_public_grant_never_widens_it() {
        let public = Authorization::public_only(&[PublicGrant::new(
            &[operations::EVENT_SUBMIT],
            Selector::parse("plane/data/*").expect("a selector"),
        )]);
        let ledger = Resource::ledger("data", "z1", "l1");
        let bearer = token(&[operations::DECISION_EVALUATE], "plane/data/zone/z1/*");
        assert_eq!(
            public
                .authorize_by(&bearer, operations::DECISION_EVALUATE, &ledger)
                .expect("its scope")
                .as_str(),
            "sa:billing"
        );
        assert_eq!(
            public
                .authorize(&bearer, operations::EVENT_SUBMIT, &ledger)
                .expect_err("public, and not the token's")
                .http_status(),
            403
        );
        assert!(
            public
                .authorize(
                    &bearer,
                    operations::DECISION_EVALUATE,
                    &Resource::ledger("data", "z2", "l1")
                )
                .is_err()
        );
        assert!(
            public
                .may_act_under(
                    &bearer,
                    operations::DECISION_EVALUATE,
                    &Resource::plane("data")
                )
                .is_ok()
        );
        assert!(!public.covers_whole(
            &bearer,
            operations::DECISION_EVALUATE,
            &Resource::plane("data")
        ));
        assert!(public.covers_whole(
            &bearer,
            operations::DECISION_EVALUATE,
            &Resource::zone("data", "z1")
        ));
        assert_eq!(
            public
                .authorize_by(&Actor::Anonymous, operations::EVENT_SUBMIT, &ledger)
                .expect("public")
                .as_str(),
            permguard_core::authz::ANONYMOUS
        );
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
                .authorize(&actor("cert:sha256:x"), operations::CATALOG_READ, &zone)
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
        assert!(
            Authorization::permissive()
                .authorize(
                    &Actor::Anonymous,
                    operations::ACCOUNTS_WRITE,
                    &Resource::plane("authority")
                )
                .is_ok()
        );
    }

    /// The bootstrap principal holds the per-Host operations on its own Host and Planes, never an
    /// evaluation, the catalog or the Authority Plane's accounts; the same principal by a token, a
    /// stranger and nobody hold nothing.
    #[test]
    fn the_bootstrap_holds_its_per_host_operations_and_nothing_more() {
        let bootstrap = Principal::new(format!("cert:sha256:{}", "ab".repeat(32))).expect("p");
        let host = Authorization::closed().with_bootstrap(Some(bootstrap.clone()));
        let actor = Actor::Authenticated(ActorContext::new(
            bootstrap.clone(),
            Credential::Certificate,
            None,
        ));
        let ledger = Resource::ledger("data", "z", "l");
        for (operation, resource) in [
            (operations::MEMBERSHIP_ADMIN, Resource::host()),
            (operations::MEMBERSHIP_READ, Resource::host()),
            (operations::IDENTITY_READ, Resource::host()),
            (operations::BACKUP_MANAGE, Resource::host()),
            (operations::KEYS_READ, Resource::plane("data")),
            (operations::KEYS_READ, ledger.clone()),
            (operations::AUDIT_READ, Resource::plane("data")),
            (operations::STREAMS_READ, Resource::plane("data")),
            (operations::GC_MANAGE, Resource::plane("data")),
        ] {
            assert_eq!(
                host.authorize_by(&actor, operation, &resource).ok(),
                Some(bootstrap.clone()),
                "{operation} on {resource}"
            );
        }
        assert!(host.covers_whole(&actor, operations::GC_MANAGE, &Resource::plane("data")));
        for (operation, resource) in [
            (operations::DECISION_EVALUATE, ledger.clone()),
            (operations::EVENT_SUBMIT, ledger.clone()),
            (operations::GC_MANAGE, Resource::host()),
            (operations::CATALOG_READ, Resource::plane("control")),
            (operations::ACCOUNTS_WRITE, Resource::plane("authority")),
            (operations::TOKENS_REVOKE, Resource::plane("authority")),
        ] {
            assert!(
                host.authorize(&actor, operation, &resource).is_err(),
                "{operation} on {resource}"
            );
        }
        let by_token = Actor::Authenticated(ActorContext::of_token(
            bootstrap.clone(),
            TokenGrant {
                scopes: vec![TokenScope {
                    operations: std::iter::once(operations::DECISION_EVALUATE.to_owned()).collect(),
                    selector: Selector::parse("plane/data/*").expect("a selector"),
                }],
                jti: "j".to_owned(),
                list_uri: "u".to_owned(),
                list_iat: 1,
                list_digest: [0; 32],
            },
        ));
        for (who, other) in [
            ("by a token", by_token),
            ("a stranger", actor_of_certificate(&"cd".repeat(32))),
            ("nobody", Actor::Anonymous),
        ] {
            assert!(
                host.authorize(&other, operations::MEMBERSHIP_ADMIN, &Resource::host())
                    .is_err(),
                "{who}"
            );
        }
    }

    fn actor_of_certificate(hex: &str) -> Actor {
        actor(&format!("cert:sha256:{hex}"))
    }
}
