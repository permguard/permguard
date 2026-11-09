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

pub mod access_tokens;
pub mod bootstrap;
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
use permguard_core::authz::{
    Actor, Allow, AllowSet, Principal, Resource, Selector, per_host_reach,
};

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
/// rule maps is unauthenticated whatever is public. An access token's bearer is the exception
/// (WP-12.2): it acts within its token, which public grants never widen; on a member, where the
/// token decides alone, they are not consulted for it at all.
pub struct Authorization {
    store: Option<Arc<GrantStore>>,
    /// The roles a principal acts with (WP-8.1); none, the principal alone.
    directory: Option<Arc<directory::Directory>>,
    public: AllowSet,
    /// Where a grant's expiry is compared against (WP-2.12).
    time: Arc<crate::time::TimeGuard>,
    /// Whether an access token's grant decides alone (a member, which holds no grants) or
    /// within the grants (the IAM Host) (WP-12.2).
    tokens_alone: bool,
    /// A member's bootstrap principal, `cert:sha256:<hex>`: on a member, it holds the per-Host
    /// operations on its own Host (WP-12.4), the only principal there that is not a token's.
    bootstrap: Option<Principal>,
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
            tokens_alone: false,
            bootstrap: None,
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
            tokens_alone: false,
            bootstrap: None,
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
    ///
    /// A system role is never one of them (`2-security/8` Roles and elevation): it holds no
    /// grants, and acts only through a token elevated to it, so a grant a role of its name held
    /// before it became the IAM Host's is never counted.
    fn subjects_of(&self, principal: &Principal) -> Vec<Principal> {
        let mut subjects = vec![principal.clone()];
        subjects.extend(self.roles_of(principal).into_iter().filter(|role| {
            role.as_str()
                .strip_prefix(directory::ROLE_PREFIX)
                .is_none_or(|name| !directory::is_system_role(name))
        }));
        subjects.push(Principal::anonymous());
        subjects
    }

    /// Every role `principal` is a member of, directly or through its provider's issuer, system
    /// roles included.
    fn roles_of(&self, principal: &Principal) -> Vec<Principal> {
        self.directory
            .as_ref()
            .map(|directory| {
                let issuer = issuer_of(principal.as_str());
                directory.subjects(principal.as_str(), issuer.as_deref())
            })
            .unwrap_or_default()
    }

    /// Decides an access token's bearer by the token's grant alone: a member, whose grants are
    /// the IAM Host's and arrive in the token (WP-12.2). Without it, a token narrows the grants
    /// and never widens them, as on the IAM Host.
    pub fn with_tokens_alone(mut self, alone: bool) -> Self {
        self.tokens_alone = alone;
        self
    }

    /// The token's verdict for `actor`, when it bears one: refused when the token does not allow
    /// it, `Some(subject)` when the token decides alone, `None` when the grants decide next.
    fn token_decides(
        &self,
        actor: &Actor,
        allowed: impl Fn(&permguard_core::authz::TokenGrant) -> bool,
    ) -> Result<Option<Principal>, AccessDenial> {
        let Actor::Authenticated(context) = actor else {
            return Ok(None);
        };
        let Some(grant) = context.token() else {
            return Ok(None);
        };
        if !allowed(grant) {
            return Err(actor.without_grant());
        }
        let principal = context.authorization_principal();
        if self.tokens_alone {
            return Ok(Some(principal.clone()));
        }
        // `2-security/8` Roles and elevation: a system role holds no grants, so on the IAM Host,
        // whose own Data Plane an all-in-one serves, a token elevated to one decides alone, as on
        // a member, while its subject is one of the role's members now. Its scope and targets
        // are what the IAM Host issued for the role, and it is checked against them above.
        if let Some(role) = grant.role.as_deref()
            && directory::is_system_role(role)
            && self.holds_role(principal, role)
        {
            return Ok(Some(principal.clone()));
        }
        Ok(None)
    }

    /// The member's bootstrap principal (WP-12.4): on a member, where the token decides alone,
    /// it holds the per-Host operations on its own Host and Planes ([`per_host_reach`]), which is
    /// how a member is joined and reached when its coordinator is lost. Ignored on the IAM Host,
    /// whose grants decide.
    pub fn with_bootstrap(mut self, principal: Option<Principal>) -> Self {
        self.bootstrap = principal;
        self
    }

    /// The bootstrap principal's standing on a member, when `actor` is it and `reach` holds.
    fn bootstrap_reaches(&self, actor: &Actor, reach: impl Fn() -> bool) -> Option<Principal> {
        let Actor::Authenticated(context) = actor else {
            return None;
        };
        let principal = context.authorization_principal();
        // The offline certificate itself, as the mapper names it: never a principal another
        // credential could come to carry.
        (self.tokens_alone
            && context.token().is_none()
            && context.credential() == permguard_core::authz::Credential::Certificate
            && self.bootstrap.as_ref() == Some(principal)
            && reach())
        .then(|| principal.clone())
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
        if let Some(decided) =
            self.token_decides(actor, |grant| grant.permits(operation, resource))?
        {
            return Ok(decided);
        }
        if let Some(bootstrap) =
            self.bootstrap_reaches(actor, || per_host_reach(operation, resource))
        {
            return Ok(bootstrap);
        }
        let allows = self.allows();
        self.subjects_of(&principal)
            .into_iter()
            .find(|subject| allows.permits(subject, operation, resource))
            .ok_or_else(|| actor.without_grant())
    }

    /// The subjects a token for `principal` may carry the grants of: itself and its roles, never
    /// the public grants of `anonymous` (`2-security/8`, a token never widens by a public grant):
    /// a token decides alone on a member, so a public grant would reach every member through it.
    fn token_subjects_of(&self, principal: &Principal) -> Vec<Principal> {
        let anonymous = Principal::anonymous();
        self.subjects_of(principal)
            .into_iter()
            .filter(|subject| *subject != anonymous)
            .collect()
    }

    /// Whose grant lets `principal` do `operation` on exactly `resource`, when one does: what the
    /// IAM Host checks before it issues a token for a subject that is not the caller (WP-11.4).
    /// A public grant never counts.
    pub fn granted_to(
        &self,
        principal: &Principal,
        operation: &str,
        resource: &Resource,
    ) -> Option<Principal> {
        let allows = self.allows();
        self.token_subjects_of(principal)
            .into_iter()
            .find(|subject| allows.permits(subject, operation, resource))
    }

    /// Whether `principal` is a member of the role `role`, directly or through its provider's
    /// issuer: whom an elevation to it is open to (`2-security/8` Roles and elevation).
    pub fn holds_role(&self, principal: &Principal, role: &str) -> bool {
        let wanted = directory::role_principal(role);
        self.roles_of(principal)
            .iter()
            .any(|subject| subject.as_str() == wanted)
    }

    /// Whether `principal` may do `operation` on everything under `scope`, whole (WP-11.4). A
    /// public grant never counts.
    pub fn principal_covers_whole(
        &self,
        principal: &Principal,
        operation: &str,
        scope: &Resource,
    ) -> bool {
        let allows = self.allows();
        self.token_subjects_of(principal)
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
        if self
            .token_decides(actor, |grant| {
                grant.permits_anywhere_under(operation, scope)
            })?
            .is_some()
        {
            return Ok(());
        }
        if self
            .bootstrap_reaches(actor, || per_host_reach(operation, scope))
            .is_some()
        {
            return Ok(());
        }
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
        match self.token_decides(actor, |grant| grant.permits_whole(operation, scope)) {
            Err(_) => return false,
            Ok(Some(_)) => return true,
            Ok(None) => {}
        }
        if self
            .bootstrap_reaches(actor, || per_host_reach(operation, scope))
            .is_some()
        {
            return true;
        }
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

    /// `2-security/8` Roles and elevation: on the IAM Host, whose own Data Plane an all-in-one
    /// serves, a token elevated to a system role decides alone, within its scope and targets and
    /// while its subject holds the role; any other token is decided by the grants too.
    #[test]
    fn a_token_elevated_to_a_system_role_decides_alone_on_the_iam_host() {
        use crate::operations::mutation::Applying;
        use crate::storage::volume::Volume;
        use directory::{Change, Directory};
        use permguard_core::authz::{TokenGrant, families};

        let root = std::env::temp_dir().join(format!("pg-authz-elevated-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        let volume = Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let (store, _) = GrantStore::open(&volume).expect("grants");
        let (directory, _) = Directory::open(&volume).expect("directory");
        let mut op = 0;
        let mut change = |change: Change| {
            op += 1;
            directory
                .apply(&Applying::for_tests(op), change, "admin", 1, None)
                .expect("applied");
        };
        for name in ["dp.01a1bc76-7028-717c-8b19-c470f894a0dd", "readers"] {
            change(Change::CreateRole {
                name: name.to_owned(),
                description: String::new(),
                max_lifetime: None,
            });
            change(Change::AddMember {
                role: name.to_owned(),
                member: "spiffe://acme/billing".to_owned(),
            });
        }
        let iam_host =
            Authorization::new(Arc::clone(&store), &[]).with_directory(Arc::clone(&directory));
        let token = |principal: &str, role: Option<&str>| {
            Actor::Authenticated(ActorContext::of_token(
                Principal::new(principal).expect("a principal"),
                TokenGrant {
                    family: families::APPLICATION.to_owned(),
                    scope: std::iter::once(operations::DECISION_EVALUATE.to_owned()).collect(),
                    targets: vec![Selector::parse("plane/data/*").expect("a selector")],
                    jti: "j".to_owned(),
                    list_uri: "u".to_owned(),
                    list_iat: 1,
                    list_digest: [0; 32],
                    authority: None,
                    role: role.map(str::to_owned),
                },
            ))
        };
        let ledger = Resource::ledger("data", "z1", "l1");
        let elevated = token(
            "spiffe://acme/billing",
            Some("dp.01a1bc76-7028-717c-8b19-c470f894a0dd"),
        );
        assert_eq!(
            iam_host
                .authorize_by(&elevated, operations::DECISION_EVALUATE, &ledger)
                .expect("the system role's token decides")
                .as_str(),
            "spiffe://acme/billing"
        );
        // Within the token only: another operation, a resource outside its targets.
        assert!(
            iam_host
                .authorize(&elevated, operations::EVENT_SUBMIT, &ledger)
                .is_err()
        );
        assert!(
            iam_host
                .authorize(
                    &elevated,
                    operations::DECISION_EVALUATE,
                    &Resource::ledger("control", "z1", "l1")
                )
                .is_err()
        );
        // Not a member of the role, an operator's role with no grant, no role: the grants decide,
        // and there are none.
        for (who, actor) in [
            (
                "a stranger",
                token(
                    "spiffe://acme/other",
                    Some("dp.01a1bc76-7028-717c-8b19-c470f894a0dd"),
                ),
            ),
            (
                "an operator's role",
                token("spiffe://acme/billing", Some("readers")),
            ),
            ("no role", token("spiffe://acme/billing", None)),
        ] {
            assert!(
                iam_host
                    .authorize(&actor, operations::DECISION_EVALUATE, &ledger)
                    .is_err(),
                "{who}"
            );
        }
        // Once the subject leaves the role, at once.
        change(Change::RemoveMember {
            role: "dp.01a1bc76-7028-717c-8b19-c470f894a0dd".to_owned(),
            member: "spiffe://acme/billing".to_owned(),
        });
        assert!(
            iam_host
                .authorize(&elevated, operations::DECISION_EVALUATE, &ledger)
                .is_err()
        );
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
                max_lifetime: None,
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

    /// TS-10: a public grant decides a request to this Host, and never goes into a token: a
    /// token decides alone on a member, where a public grant would reach every member through it.
    #[test]
    fn a_public_grant_never_counts_for_a_token() {
        let public = Authorization::public_only(&[PublicGrant::new(
            &[operations::DECISION_EVALUATE],
            Selector::parse("plane/data/*").expect("a selector"),
        )]);
        let ledger = Resource::ledger("data", "z1", "l1");
        let anybody = Principal::new("sa:billing").expect("a principal");
        assert!(
            public
                .authorize(&actor("sa:billing"), operations::DECISION_EVALUATE, &ledger)
                .is_ok(),
            "public to everybody here"
        );
        assert_eq!(
            public.granted_to(&anybody, operations::DECISION_EVALUATE, &ledger),
            None
        );
        assert!(!public.principal_covers_whole(
            &anybody,
            operations::DECISION_EVALUATE,
            &Resource::plane("data")
        ));
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

    /// WP-12.4: on a member, its bootstrap principal holds the per-Host operations on its own Host
    /// and Planes, never an evaluation and never what the IAM Host administers; the same principal
    /// by another credential or a token, a stranger and nobody hold nothing; and on the IAM Host
    /// the bootstrap is decided by its grants alone.
    #[test]
    fn a_members_bootstrap_holds_its_per_host_operations_and_nothing_more() {
        use permguard_core::authz::{ActorContext, Credential, TokenGrant, families, operations};

        let bootstrap = Principal::new(format!("cert:sha256:{}", "ab".repeat(32))).expect("p");
        let by = |principal: &Principal, credential: Credential| {
            Actor::Authenticated(ActorContext::new(principal.clone(), credential, None))
        };
        let member = Authorization::closed()
            .with_tokens_alone(true)
            .with_bootstrap(Some(bootstrap.clone()));
        let actor = by(&bootstrap, Credential::Certificate);
        let ledger = Resource::ledger("data", "z", "l");
        let allowed = [
            (operations::MEMBERSHIP_ADMIN, Resource::host()),
            (operations::MEMBERSHIP_READ, Resource::host()),
            (operations::IDENTITY_READ, Resource::host()),
            (operations::BACKUP_MANAGE, Resource::host()),
            (operations::KEYS_READ, Resource::plane("data")),
            (operations::KEYS_READ, ledger.clone()),
            (operations::AUDIT_READ, Resource::plane("data")),
            (operations::STREAMS_READ, Resource::plane("data")),
            (operations::GC_MANAGE, Resource::plane("data")),
        ];
        for (operation, resource) in &allowed {
            assert_eq!(
                member.authorize_by(&actor, operation, resource).ok(),
                Some(bootstrap.clone()),
                "{operation} on {resource}"
            );
        }
        assert!(
            member
                .may_act_under(&actor, operations::KEYS_READ, &Resource::plane("data"))
                .is_ok()
        );
        assert!(member.covers_whole(&actor, operations::GC_MANAGE, &Resource::plane("data")));
        assert!(
            member
                .may_act_under(
                    &actor,
                    operations::DECISION_EVALUATE,
                    &Resource::plane("data")
                )
                .is_err()
        );
        assert!(!member.covers_whole(
            &actor,
            operations::DECISION_EVALUATE,
            &Resource::plane("data")
        ));
        for (operation, resource) in [
            (operations::DECISION_EVALUATE, ledger.clone()),
            (operations::EVENT_SUBMIT, ledger.clone()),
            (operations::AUTHZ_ADMIN, Resource::host()),
            (operations::GC_MANAGE, Resource::host()),
            (operations::CATALOG_READ, Resource::plane("control")),
            (operations::MEMBERSHIP_ADMIN, Resource::member("m")),
            (operations::MEMBERSHIP_READ, Resource::Members),
        ] {
            assert!(
                member.authorize(&actor, operation, &resource).is_err(),
                "{operation} on {resource}"
            );
        }
        // The same principal by another credential, a token naming it, a stranger, nobody.
        let by_token = Actor::Authenticated(ActorContext::of_token(
            bootstrap.clone(),
            TokenGrant {
                family: families::APPLICATION.to_owned(),
                scope: std::iter::once(operations::DECISION_EVALUATE.to_owned()).collect(),
                targets: vec![Selector::parse("plane/data/*").expect("a selector")],
                jti: "j".to_owned(),
                list_uri: "u".to_owned(),
                list_iat: 1,
                list_digest: [0; 32],
                authority: None,
                role: None,
            },
        ));
        let stranger = by(
            &Principal::new(format!("cert:sha256:{}", "cd".repeat(32))).expect("p"),
            Credential::Certificate,
        );
        for (who, other) in [
            ("by a SAN URI", by(&bootstrap, Credential::SanUri)),
            ("by a token", by_token),
            ("a stranger", stranger),
            ("nobody", Actor::Anonymous),
        ] {
            assert!(
                member
                    .authorize(&other, operations::MEMBERSHIP_ADMIN, &Resource::host())
                    .is_err(),
                "{who}"
            );
        }
        let iam_host = Authorization::closed().with_bootstrap(Some(bootstrap.clone()));
        assert!(
            iam_host
                .authorize(&actor, operations::MEMBERSHIP_ADMIN, &Resource::host())
                .is_err(),
            "the IAM Host's grants decide"
        );
    }
}
