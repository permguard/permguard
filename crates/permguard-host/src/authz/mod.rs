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

pub mod credentials;
pub mod directory;
pub mod factor;
pub mod lockout;
pub mod mapper;
pub mod oidc;
pub mod password;
pub mod record;
pub mod sessions;
pub mod signin;
pub mod store;
pub mod tokens;

use std::sync::Arc;

use permguard_core::AccessDenial;
use permguard_core::authz::{Actor, Allow, AllowSet, Principal, Resource, Selector};

pub use mapper::{Accounts, MapperError, PrincipalMapper, Rule};
pub use oidc::{KeySource, KeyState, OidcRule, ProviderStatus, Verifier};
pub use record::{GrantId, GrantRecord, Status};
pub use store::{AuthzError, Bootstrap, Change, GrantStore, Issue, validate_issue};

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
    /// The roles a principal acts with (WP-8.1); none, the principal alone.
    directory: Option<Arc<directory::Directory>>,
    public: AllowSet,
    /// Where a grant's expiry is compared against (WP-2.12).
    time: Arc<crate::time::TimeGuard>,
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
            directory: None,
            public: public_allows(public),
            time: Arc::new(crate::time::TimeGuard::system(
                permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
            )),
        }
    }

    /// Public grants only, no store: what a test, or a composition without a volume, uses.
    pub fn public_only(public: &[PublicGrant]) -> Self {
        Self {
            store: None,
            directory: None,
            public: public_allows(public),
            time: Arc::new(crate::time::TimeGuard::system(
                permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
            )),
        }
    }

    /// Compares grant expiry against `time`, the Host's guard, instead of a guard of its own.
    /// Decides with the roles the directory holds: a principal acts as itself and as every role
    /// it, or its provider's issuer, is a member of (`1-architecture/1` Authorization model).
    pub fn with_directory(mut self, directory: Arc<directory::Directory>) -> Self {
        self.directory = Some(directory);
        self
    }

    /// Every subject whose grants `principal` acts with: itself, its roles, the roles of its
    /// issuer, and last the reserved `anonymous`, whose grants are public to everybody.
    fn subjects_of(&self, principal: &Principal) -> Vec<Principal> {
        let mut subjects = vec![principal.clone()];
        if let Some(directory) = &self.directory {
            let issuer = issuer_of(principal.as_str());
            subjects.extend(directory.subjects(principal.as_str(), issuer.as_deref()));
        }
        subjects.push(Principal::anonymous());
        subjects
    }

    pub fn with_time(mut self, time: Arc<crate::time::TimeGuard>) -> Self {
        self.time = time;
        self
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
        let now = self.time.now_secs();
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
        self.authorize_by(actor, operation, resource).map(|_| ())
    }

    /// [`Authorization::authorize`], answering whose grant allowed it: the principal itself, a
    /// role, or `anonymous` for a public grant. What the audit names (WP-8.1).
    pub fn authorize_by(
        &self,
        actor: &Actor,
        operation: &str,
        resource: &Resource,
    ) -> Result<Principal, AccessDenial> {
        let principal = actor.principal()?;
        let allows = self.allows();
        self.subjects_of(&principal)
            .into_iter()
            .find(|subject| allows.permits(subject, operation, resource))
            .ok_or_else(|| actor.without_grant())
    }

    /// Whose grant lets `principal` do `operation` on exactly `resource`, when one does: what the
    /// IAM Host checks before it issues a token for a subject that is not the caller (WP-11.4).
    pub fn granted_to(
        &self,
        principal: &Principal,
        operation: &str,
        resource: &Resource,
    ) -> Option<Principal> {
        let allows = self.allows();
        self.subjects_of(principal)
            .into_iter()
            .find(|subject| allows.permits(subject, operation, resource))
    }

    /// Whether `principal` may do `operation` on everything under `scope`, whole (WP-11.4).
    pub fn principal_covers_whole(
        &self,
        principal: &Principal,
        operation: &str,
        scope: &Resource,
    ) -> bool {
        let allows = self.allows();
        self.subjects_of(principal)
            .iter()
            .any(|subject| allows.permits_whole(subject, operation, scope))
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
        if self
            .subjects_of(&principal)
            .iter()
            .any(|subject| allows.permits_anywhere_under(subject, operation, scope))
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
        self.subjects_of(&principal)
            .iter()
            .any(|subject| allows.permits_whole(subject, operation, scope))
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

/// `oidc:<issuer>` for a provider subject `oidc:<issuer>#<value>`; nothing for any other.
pub fn issuer_of(principal: &str) -> Option<String> {
    principal
        .strip_prefix("oidc:")
        .and_then(|rest| rest.split_once('#'))
        .map(|(issuer, _)| format!("oidc:{issuer}"))
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
    fn a_member_acts_with_its_roles_grants_and_an_issuer_member_stands_for_every_subject() {
        use crate::operations::mutation::Applying;
        use crate::storage::volume::Volume;
        use directory::{Change, Directory};

        let root = std::env::temp_dir().join(format!("pg-authz-roles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        let volume = Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("grants");
        let (directory, _) = Directory::open(&volume).expect("directory");
        store
            .issue(
                &Applying::for_tests(1),
                Issue {
                    principal: Principal::new("role:readers").expect("a principal"),
                    operations: vec![operations::CATALOG_READ.to_owned()],
                    selector: Selector::parse("plane/control/*").expect("a selector"),
                    resource_types: vec!["*".to_owned()],
                    constraints: Default::default(),
                    issued_by: "test".to_owned(),
                    expires_at: None,
                },
                1_800_000_000,
                None,
            )
            .expect("issued");
        let change = |op: u8, change: Change| {
            directory
                .apply(&Applying::for_tests(op), change, "admin", 1, None)
                .expect("applied");
        };
        change(
            2,
            Change::CreateRole {
                name: "readers".to_owned(),
                description: String::new(),
            },
        );
        change(
            3,
            Change::AddMember {
                role: "readers".to_owned(),
                member: "spiffe://acme/billing".to_owned(),
            },
        );
        change(
            4,
            Change::AddMember {
                role: "readers".to_owned(),
                member: "oidc:https://login.example".to_owned(),
            },
        );
        let authorization =
            Authorization::new(Arc::clone(&store), &[]).with_directory(Arc::clone(&directory));
        let zone = Resource::zone("control", "z1");
        assert_eq!(
            authorization
                .authorize_by(
                    &actor("spiffe://acme/billing"),
                    operations::CATALOG_READ,
                    &zone
                )
                .expect("allowed")
                .as_str(),
            "role:readers",
            "the role's grant allowed it"
        );
        assert!(
            authorization
                .authorize(
                    &actor("oidc:https://login.example#anybody"),
                    operations::CATALOG_READ,
                    &zone
                )
                .is_ok()
        );
        assert!(
            authorization
                .authorize(
                    &actor("oidc:https://other.example#x"),
                    operations::CATALOG_READ,
                    &zone
                )
                .is_err()
        );
        assert!(
            authorization
                .authorize(
                    &actor("spiffe://acme/stranger"),
                    operations::CATALOG_READ,
                    &zone
                )
                .is_err()
        );
        assert!(
            authorization
                .authorize(
                    &actor("spiffe://acme/billing"),
                    operations::CATALOG_WRITE,
                    &zone
                )
                .is_err()
        );
        // Removed: refused at the next decision, with no cache to outlive it.
        change(
            5,
            Change::RemoveMember {
                role: "readers".to_owned(),
                member: "spiffe://acme/billing".to_owned(),
            },
        );
        assert!(
            authorization
                .authorize(
                    &actor("spiffe://acme/billing"),
                    operations::CATALOG_READ,
                    &zone
                )
                .is_err()
        );
        assert_eq!(
            issuer_of("oidc:https://login.example#a#b").as_deref(),
            Some("oidc:https://login.example")
        );
        assert_eq!(issuer_of("spiffe://acme/billing"), None);
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
