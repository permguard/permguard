// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The bootstrap principal on a joined member (iteration 02, WP-12.4, `2-security/8` Before a
//! member joins): the one credential a member admits besides its IAM Host's access tokens. It
//! brings a Host into a cluster and reaches it when its coordinator is lost; once the Host is a
//! member, every use is a break-glass: audited `host.authz.bootstrap`, and reported by health as
//! `degraded: bootstrap` until [`DEGRADED_FOR`] after the last one.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use permguard_core::authz::{Actor, Authenticator, Principal};

/// The capability health reports degraded while the bootstrap principal is in use.
pub const CAPABILITY: &str = "bootstrap";
/// How long after its last use the bootstrap principal is reported.
pub const DEGRADED_FOR: Duration = Duration::from_secs(15 * 60);

/// Whether a Host has joined: the memberships it holds as a member, active or suspended. A
/// suspended one counts: a coordinator lost is exactly when a member is reached by its bootstrap.
pub trait Joined: Send + Sync {
    fn memberships(&self) -> usize;
}

/// Whether a membership in `role` and `status` makes its Host joined.
pub fn joins(
    role: crate::membership::record::Role,
    status: crate::membership::record::Status,
) -> bool {
    use crate::membership::record::{Role, Status};

    role == Role::Member && matches!(status, Status::Active | Status::Suspended)
}

impl Joined for crate::membership::Store {
    fn memberships(&self) -> usize {
        crate::membership::Store::memberships(self)
            .into_iter()
            .filter(|(_, held)| joins(held.role, held.status))
            .count()
    }
}

/// The Host's authenticator, watching its bootstrap principal. A use is recorded before the
/// request goes on; a record the trail cannot take leaves the request admitted, since the
/// bootstrap is how a member is reached when everything else failed, and is reported louder.
pub struct BootstrapWatch {
    pub inner: Arc<dyn Authenticator>,
    /// `cert:sha256:<hex>`, as the commitment names it.
    pub principal: Principal,
    pub members: Arc<dyn Joined>,
    pub audit: Option<Arc<crate::audit::Engine>>,
    pub health: permguard_core::server::Health,
    time: Arc<crate::time::TimeGuard>,
    degraded_for: Duration,
    /// The second of the last use on the guarded clock; 0 while none is reported.
    last: AtomicU64,
}

impl BootstrapWatch {
    pub fn new(
        inner: Arc<dyn Authenticator>,
        principal: Principal,
        members: Arc<dyn Joined>,
        audit: Option<Arc<crate::audit::Engine>>,
        health: permguard_core::server::Health,
        time: Arc<crate::time::TimeGuard>,
    ) -> Self {
        Self {
            inner,
            principal,
            members,
            audit,
            health,
            time,
            degraded_for: DEGRADED_FOR,
            last: AtomicU64::new(0),
        }
    }

    /// Records one use on a joined member and reports it.
    fn used(&self, memberships: usize) {
        let mut recorded = true;
        if let Some(audit) = &self.audit {
            let count = u64::try_from(memberships).unwrap_or(u64::MAX);
            let facts = [("memberships", permguard_core::Fact::Uint(count))];
            let event = permguard_core::AuditEvent::new(
                crate::audit::AUDIT_AUTHZ_BOOTSTRAP,
                permguard_core::Subject::Principal(self.principal.as_str()),
            )
            .with_facts(&facts);
            if let Err(error) = audit.append(&event, None) {
                recorded = false;
                tracing::error!(
                    event.name = "host.authz_bootstrap_unrecorded",
                    component = "host",
                    error = %error,
                    "a use of the bootstrap principal could not be recorded in the audit trail"
                );
            }
        }
        tracing::warn!(
            event.name = "host.authz_bootstrap",
            component = "host",
            memberships,
            "the bootstrap principal acts on a joined member"
        );
        let now = self.time.now_secs().max(1);
        self.last.store(now, Ordering::SeqCst);
        let at = permguard_core::time::to_rfc3339(i64::try_from(now).unwrap_or(i64::MAX));
        self.health.lifecycle().degrade(
            permguard_core::lifecycle::HOST,
            CAPABILITY,
            if recorded {
                format!("the bootstrap principal acted on this joined member, last at {at}")
            } else {
                format!(
                    "the bootstrap principal acted on this joined member, last at {at}, and the \
                     audit trail did not take the record"
                )
            },
        );
    }

    /// Clears the report once [`DEGRADED_FOR`] has passed since the last use: run on every
    /// request and on the server's tick, so an idle member clears too.
    pub fn expire(&self) {
        let last = self.last.load(Ordering::SeqCst);
        if last == 0 || self.time.now_secs().saturating_sub(last) < self.degraded_for.as_secs() {
            return;
        }
        if self
            .last
            .compare_exchange(last, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.health
                .lifecycle()
                .restore(permguard_core::lifecycle::HOST, CAPABILITY);
        }
    }
}

impl Authenticator for BootstrapWatch {
    fn authenticate(
        &self,
        peer: Option<&permguard_core::PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<Actor, permguard_core::AccessDenial> {
        self.expire();
        let actor = self.inner.authenticate(peer, bearer)?;
        if let Actor::Authenticated(context) = &actor
            && *context.authorization_principal() == self.principal
        {
            let memberships = self.members.memberships();
            if memberships > 0 {
                self.used(memberships);
            }
        }
        Ok(actor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::atomic::AtomicUsize;

    use super::*;
    use permguard_core::authz::{ActorContext, Credential};

    const BOOTSTRAP: &str =
        "cert:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct Count(AtomicUsize);

    impl Joined for Count {
        fn memberships(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// `Bearer <principal>` acts as that principal.
    struct Names;

    impl Authenticator for Names {
        fn authenticate(
            &self,
            _peer: Option<&permguard_core::PeerIdentity>,
            bearer: Option<&str>,
        ) -> Result<Actor, permguard_core::AccessDenial> {
            Ok(Actor::Authenticated(ActorContext::new(
                Principal::new(bearer.unwrap_or("anonymous")).expect("a principal"),
                Credential::Certificate,
                None,
            )))
        }
    }

    fn reasons(health: &permguard_core::server::Health) -> Vec<String> {
        health
            .lifecycle()
            .report(permguard_core::lifecycle::HOST)
            .degraded
            .iter()
            .filter(|degraded| degraded.capability == CAPABILITY)
            .map(|degraded| degraded.reason.clone())
            .collect()
    }

    /// Before a Host joins its bootstrap principal is its administrator, nothing to report; once
    /// joined every use is reported with its time, and the tick clears the report its window
    /// after the last use.
    #[test]
    fn the_bootstrap_principal_is_reported_only_on_a_joined_member() {
        let health = permguard_core::server::Health::new();
        let joined = Arc::new(Count(AtomicUsize::new(0)));
        let mut watch = BootstrapWatch::new(
            Arc::new(Names),
            Principal::new(BOOTSTRAP).expect("a principal"),
            Arc::clone(&joined) as Arc<dyn Joined>,
            None,
            health.clone(),
            Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30))),
        );
        watch.authenticate(None, Some(BOOTSTRAP)).expect("acts");
        assert!(
            reasons(&health).is_empty(),
            "not joined: the bootstrap is the administrator"
        );

        joined.0.store(1, Ordering::SeqCst);
        watch
            .authenticate(None, Some("spiffe://acme/other"))
            .expect("acts");
        assert!(
            reasons(&health).is_empty(),
            "another principal is not the bootstrap"
        );
        let actor = watch.authenticate(None, Some(BOOTSTRAP)).expect("acts");
        assert!(matches!(actor, Actor::Authenticated(_)), "still admitted");
        let reported = reasons(&health);
        assert_eq!(
            reported.len(),
            1,
            "a break-glass on a joined member is reported"
        );
        assert!(
            reported[0].contains("last at 20"),
            "it names when: {reported:?}"
        );

        // Within its window the report stays; past it, the tick clears it, idle or not.
        watch.expire();
        assert_eq!(reasons(&health).len(), 1);
        watch.degraded_for = Duration::ZERO;
        watch.expire();
        assert!(
            reasons(&health).is_empty(),
            "cleared once the window passed"
        );
    }

    /// A suspended membership is still a joined Host: a coordinator lost is when the bootstrap
    /// is used. A pending one, or one that ended, is not; a coordinator's never is.
    #[test]
    fn a_member_is_joined_while_its_membership_is_active_or_suspended() {
        use crate::membership::record::{Role, Status};

        assert!(joins(Role::Member, Status::Active));
        assert!(joins(Role::Member, Status::Suspended));
        for status in [
            Status::Pending,
            Status::Revoked,
            Status::Rejected,
            Status::Expired,
            Status::Orphaned,
        ] {
            assert!(!joins(Role::Member, status), "{status:?}");
        }
        assert!(!joins(Role::Coordinator, Status::Active));
    }
}
