// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Role elevation (`2-security/8` Roles and elevation): a subject asks `scope=role:<name>` and the
//! security token service issues a token within that role alone.
//!
//! | Role                 | Permissions on elevation                                            | Audience                  |
//! | -------------------- | ------------------------------------------------------------------- | ------------------------- |
//! | one an operator made | the grants of `role:<name>` alone                                   | as asked                  |
//! | `dp.<member_id>`     | the application operations on that member, `plane/data/*` by default | exactly `member:<id>`    |
//! | `data-planes`        | the application operations on every member                          | as asked                  |
//!
//! The system roles hold no grants: they act only through elevation, so a member of one gains
//! nothing in a token issued without a role. They follow the live members, reconciled at every
//! approval, every end and every token sync.

use std::collections::{BTreeMap, BTreeSet};

use permguard_core::authz::Principal;

use super::HostApi;
use super::federation::Subject;
use super::token_endpoint::{
    APPLICATION, APPLICATION_OPERATIONS, Asked, TokenRefusal, TokenRequest, selectors_of,
};
use crate::authz::directory::{Change, role_principal};
use crate::identity::record::uuid_text;
use crate::operations::journal::Initiator;

pub use crate::authz::directory::{
    DATA_PLANES_ROLE, MEMBER_ROLE_PREFIX, is_system_role, member_role,
};
/// What a system role's token targets when the request names none: the whole of a member's
/// data plane, which only the member it is addressed to serves.
pub const DATA_PLANE_TARGET: &str = "plane/data/*";
/// Who makes and ends the system roles, in the directory's journal and its audit.
const SYSTEM: &str = "membership";

impl HostApi {
    /// What an elevation of `subject` to `role` asks: within the role's permissions alone, and
    /// only for one of its members. Which rule failed is said, never whether the role exists.
    pub(super) fn elevated(
        &self,
        request: &TokenRequest,
        subject: &Subject,
        role: &str,
        operations: &[&str],
    ) -> Result<Asked, TokenRefusal> {
        let identities = self
            .identities
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no directory is open".to_owned()))?;
        if identities.directory.role(role).is_none()
            || !self.authorization.holds_role(&subject.principal, role)
        {
            return Err(TokenRefusal::InvalidScope(
                "the subject may not elevate to the role the scope names".to_owned(),
            ));
        }
        let mut asked = if is_system_role(role) {
            self.data_plane_role(request, role, operations)?
        } else {
            let holder = Principal::new(role_principal(role))
                .map_err(|_| TokenRefusal::InvalidScope("the scope names no role".to_owned()))?;
            if operations.is_empty() {
                return Err(TokenRefusal::InvalidScope(
                    "an elevation to an operator's role names the operations it asks".to_owned(),
                ));
            }
            // D20: a service account administers only by its own grants, never through a role.
            if subject.account.is_some()
                && !operations
                    .iter()
                    .all(|op| APPLICATION_OPERATIONS.contains(op))
            {
                return Err(TokenRefusal::InvalidScope(
                    "a service account elevates to decide only: administration is its own grants'"
                        .to_owned(),
                ));
            }
            self.within_grants(request, subject, &holder, operations)?
        };
        asked.role = Some(role.to_owned());
        Ok(asked)
    }

    /// A system role's ask: the application operations, all of them unless narrowed, on the data
    /// plane of its member, or of the members asked for `data-planes`.
    fn data_plane_role(
        &self,
        request: &TokenRequest,
        role: &str,
        operations: &[&str],
    ) -> Result<Asked, TokenRefusal> {
        let operations: Vec<&str> = if operations.is_empty() {
            APPLICATION_OPERATIONS.to_vec()
        } else {
            operations.to_vec()
        };
        if !operations
            .iter()
            .all(|op| APPLICATION_OPERATIONS.contains(op))
        {
            return Err(TokenRefusal::InvalidScope(
                "a data plane role decides: it carries application operations only".to_owned(),
            ));
        }
        let audience = match role.strip_prefix(MEMBER_ROLE_PREFIX) {
            Some(member_id) => {
                let own = format!("member:{member_id}");
                if !request.audience.is_empty() && request.audience.iter().any(|aud| *aud != own) {
                    return Err(TokenRefusal::InvalidTarget(
                        "a member's role is addressed to its member alone".to_owned(),
                    ));
                }
                vec![own]
            }
            None => request.audience.clone(),
        };
        let audience = self.checked_audience(&audience, APPLICATION)?;
        let asked_targets = if request.target.is_empty() {
            vec![DATA_PLANE_TARGET.to_owned()]
        } else {
            request.target.clone()
        };
        let mut targets = BTreeSet::new();
        for selector in selectors_of(&asked_targets)? {
            if selector.prefix().plane_id() != Some("data") {
                return Err(TokenRefusal::InvalidTarget(format!(
                    "`{selector}` is not under {DATA_PLANE_TARGET}: a data plane role decides there"
                )));
            }
            targets.insert(selector.to_string());
        }
        Ok(Asked {
            family: APPLICATION,
            scope: operations.iter().map(|op| (*op).to_owned()).collect(),
            audience,
            targets: targets.into_iter().collect(),
            role: None,
        })
    }

    /// The system roles brought to the live members after a membership changed: what it made and
    /// ended is logged; a failure is logged and left to the next token sync, which reconciles
    /// again.
    pub fn member_roles_follow(&self) {
        match self.reconcile_member_roles() {
            Ok((made, ended)) if made.is_empty() && ended.is_empty() => {}
            Ok((made, ended)) => tracing::info!(
                event.name = "iam.member_roles",
                component = super::COMPONENT,
                made = made.join(" "),
                ended = ended.join(" "),
                "the members' roles follow the live members"
            ),
            Err(error) => tracing::warn!(
                event.name = "iam.member_roles_unreconciled",
                component = super::COMPONENT,
                error = %error,
                "the members' roles could not follow the live members; the next token sync retries"
            ),
        }
    }

    /// Aligns the system roles with the live members: `dp.<member_id>` for each, `data-planes`
    /// once there is one, and a member role whose member is gone ended. Idempotent, so it runs
    /// after every approval and end and at every token sync, and a crash between a membership's
    /// change and its role's leaves nothing behind. Answers the roles it made and ended.
    pub fn reconcile_member_roles(&self) -> Result<(Vec<String>, Vec<String>), String> {
        let (Some(identities), Some(mutations)) =
            (self.identities.as_ref(), self.mutations.as_ref())
        else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut live: BTreeMap<String, String> = self
            .memberships
            .as_ref()
            .map(|service| service.store.live_members())
            .unwrap_or_default()
            .into_iter()
            .map(|(record, _)| (member_role(&uuid_text(&record.member_id)), record.name))
            .collect();
        // A Server that runs both Planes is a member of itself.
        if let Some(tokens) = self.tokens.as_deref() {
            let local = tokens.local_member();
            if tokens.is_local_member(&local)
                && let Some(member_id) = local.strip_prefix("member:")
            {
                live.insert(member_role(member_id), "this Host".to_owned());
            }
        }
        let held: BTreeSet<String> = identities
            .directory
            .roles()
            .into_iter()
            .map(|role| role.name)
            .filter(|name| name.starts_with(MEMBER_ROLE_PREFIX))
            .collect();
        let now = self.time.now_secs();
        let apply = |change: Change| {
            crate::operations::directory::change(
                mutations,
                &identities.directory,
                Initiator::System(SYSTEM.to_owned()),
                change,
                SYSTEM,
                now,
                None,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        };
        let mut made = Vec::new();
        if !live.is_empty() && identities.directory.role(DATA_PLANES_ROLE).is_none() {
            apply(Change::CreateRole {
                name: DATA_PLANES_ROLE.to_owned(),
                description: "decide on every data plane, by elevation".to_owned(),
            })?;
            made.push(DATA_PLANES_ROLE.to_owned());
        }
        for (name, member) in &live {
            if !held.contains(name) {
                apply(Change::CreateRole {
                    name: name.clone(),
                    description: format!("decide on the data plane of {member}, by elevation"),
                })?;
                made.push(name.clone());
            }
        }
        let mut ended = Vec::new();
        for name in held.iter().filter(|name| !live.contains_key(*name)) {
            apply(Change::DeleteRole { name: name.clone() })?;
            ended.push(name.clone());
        }
        Ok((made, ended))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_roles_are_named_apart() {
        let id = "01a1bc76-7028-717c-8b19-c470f894a0dd";
        assert_eq!(member_role(id), format!("dp.{id}"));
        assert!(member_role(id).len() <= 63, "a role name's bound");
        assert!(is_system_role(&member_role(id)));
        assert!(is_system_role(DATA_PLANES_ROLE));
        assert!(!is_system_role("billing-readers"));
        assert!(!is_system_role("data-planes-extra"));
    }
}
