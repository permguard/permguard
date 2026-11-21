// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The service accounts (`2-security/8` Service accounts): their scopes and access keys, and the
//! contract their store keeps (`1-architecture/8` Store contracts).
//!
//! | Here               | What                                                                       |
//! | ------------------ | -------------------------------------------------------------------------- |
//! | [`Account`]        | one service account as it stands, its keys as Argon2id hashes only         |
//! | [`validate`]       | what no store ever writes: a name, a description, scopes, more live keys   |
//! | [`AccountStore`]   | the contract: every way the Authority Plane reads and changes its accounts |
//! | [`files`]          | the file backend: one journal on the volume                                |
//! | [`suite`]          | the conformance suite every backend of the contract passes                 |
//!
//! | Rule of the contract                         | Where                                              |
//! | -------------------------------------------- | -------------------------------------------------- |
//! | an account is valid, or it is not written    | [`AccountStore::create`], [`AccountStore::update`] |
//! | an access key names one key of one account   | [`AccountStore::create`], [`AccountStore::update`] |
//! | at most [`MAX_ACCOUNTS`] accounts            | [`AccountStore::create`]                           |
//! | a change reads the account it replaces       | [`AccountStore::update`], [`AccountStore::delete`] |
//! | `admin` is never deleted                     | [`AccountStore::delete`]                           |
//! | an operation changes the accounts once       | every change                                       |
//! | the revision rises by one with every change  | [`AccountStore::revision`]                         |

use permguard_core::authz::{
    MAX_TOKEN_SCOPES, Resource, Selector, TokenScope, operation_fits, operations,
};
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::{Applying, Domain, Observed};

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

/// The domain the accounts' mutations run in.
pub const DOMAIN: &str = "authority.accounts";
/// The administrator every Authority Plane makes at its first start.
pub const ADMIN: &str = "admin";
/// The most accounts one Authority Plane holds.
pub const MAX_ACCOUNTS: usize = 10_000;
/// The most live access keys of one account: room for a rotation's overlap, no more.
pub const MAX_LIVE_KEYS: usize = 2;
/// The longest description, in bytes.
pub const MAX_DESCRIPTION: usize = 1_024;
/// The principal of the account `name`.
pub fn principal_of(name: &str) -> String {
    format!("sa:{name}")
}

/// Whether an account may obtain tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Suspended,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// One access key of an account; its secret only as a hash.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessKey {
    pub access_key: String,
    pub secret_hash: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl std::fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessKey")
            .field("access_key", &self.access_key)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl AccessKey {
    /// Whether the key may obtain a token at `now`.
    pub fn is_live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|expires| now < expires)
    }
}

/// One service account, as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub description: String,
    pub status: Status,
    pub scopes: Vec<TokenScope>,
    pub keys: Vec<AccessKey>,
    pub created_at: u64,
    pub updated_at: u64,
    /// The journal revision of its last change.
    pub revision: u64,
}

impl Account {
    /// A new active account with no key.
    pub fn new(name: &str, description: &str, scopes: Vec<TokenScope>, now: u64) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            status: Status::Active,
            scopes,
            keys: Vec::new(),
            created_at: now,
            updated_at: now,
            revision: 0,
        }
    }

    /// Whether it is the administrator: never deleted, suspended or narrowed.
    pub fn is_admin(&self) -> bool {
        self.name == ADMIN
    }

    /// Its keys live at `now`.
    pub fn live_keys(&self, now: u64) -> impl Iterator<Item = &AccessKey> {
        self.keys.iter().filter(move |key| key.is_live(now))
    }

    /// The key `access_key` names.
    pub fn key(&self, access_key: &str) -> Option<&AccessKey> {
        self.keys.iter().find(|key| key.access_key == access_key)
    }
}

/// The administrator's scopes: every registered operation on every resource, one scope per
/// resource kind so each stays coherent.
pub fn admin_scopes() -> Vec<TokenScope> {
    [
        Resource::host(),
        Resource::plane("authority"),
        Resource::plane("control"),
        Resource::plane("data"),
    ]
    .into_iter()
    .map(|resource| {
        let selector = Selector::under(resource);
        TokenScope {
            operations: operations::ALL
                .iter()
                .filter(|operation| operation_fits(operation, &selector))
                .map(|operation| (*operation).to_owned())
                .collect(),
            selector,
        }
    })
    .collect()
}

/// Checks an account name: 1 to 63 lowercase letters, digits, `-`, `_`, `.`, starting with a
/// letter or a digit.
pub fn check_name(name: &str) -> Result<(), String> {
    let valid = (1..=63).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(format!(
            "`{name}` is not an account name: 1 to 63 of a-z, 0-9, `-`, `_` and `.`, starting \
             with a letter or a digit"
        ))
    }
}

/// Checks a description: at most [`MAX_DESCRIPTION`] bytes, no control character.
pub fn check_description(description: &str) -> Result<(), String> {
    if description.len() > MAX_DESCRIPTION {
        return Err(format!(
            "a description takes at most {MAX_DESCRIPTION} bytes"
        ));
    }
    if description.chars().any(char::is_control) {
        return Err("a description holds no control character".to_owned());
    }
    Ok(())
}

/// Checks a set of scopes: at most [`MAX_TOKEN_SCOPES`], each naming registered operations
/// only, every one of which fits its selector (`2-security/6` Scope coherence).
pub fn check_scopes(scopes: &[TokenScope]) -> Result<(), String> {
    if scopes.len() > MAX_TOKEN_SCOPES {
        return Err(format!(
            "an account holds at most {MAX_TOKEN_SCOPES} scopes"
        ));
    }
    for (position, scope) in scopes.iter().enumerate() {
        if scope.operations.is_empty() {
            return Err(format!("scope {position} names no operation"));
        }
        for operation in &scope.operations {
            if !operations::is_registered(operation) {
                return Err(format!(
                    "scope {position} names `{operation}`, which is not a registered operation"
                ));
            }
            if !operation_fits(operation, &scope.selector) {
                return Err(format!(
                    "scope {position}: `{operation}` never applies under `{}`",
                    scope.selector
                ));
            }
        }
    }
    Ok(())
}

/// What a store refuses, and what it could not do.
#[derive(Debug)]
pub enum AccountsError {
    /// A request the store would never write.
    Invalid(String),
    /// What the change needs is not there.
    NotFound(String),
    /// What the change would make collides with what is there.
    Conflict(String),
    /// The store did not answer, or what it holds does not read: nothing is known of the change.
    Unavailable(String),
}

impl std::fmt::Display for AccountsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail)
            | Self::NotFound(detail)
            | Self::Conflict(detail)
            | Self::Unavailable(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for AccountsError {}

/// Refuses what no store writes, in the order the refusals are answered: the name, the
/// description, the scopes, then more than [`MAX_LIVE_KEYS`] keys live at `now`. Every backend
/// calls it on what it is about to write.
pub fn validate(account: &Account, now: u64) -> Result<(), AccountsError> {
    check_name(&account.name).map_err(AccountsError::Invalid)?;
    check_description(&account.description).map_err(AccountsError::Invalid)?;
    check_scopes(&account.scopes).map_err(AccountsError::Invalid)?;
    if account.live_keys(now).count() > MAX_LIVE_KEYS {
        return Err(AccountsError::Conflict(format!(
            "an account holds at most {MAX_LIVE_KEYS} live access keys: delete one first"
        )));
    }
    Ok(())
}

/// The accounts of one Authority Plane: the only way its code reads and changes them.
///
/// A call holds one complete rule: what it checks and what it writes are never two calls a
/// caller could interleave. A read answers accounts whose change was committed.
pub trait AccountStore: Send + Sync + std::fmt::Debug {
    /// The number of changes applied: it rises by one with every change that succeeds, and
    /// never otherwise.
    fn revision(&self) -> Result<u64, AccountsError>;

    /// The account `name`, while held.
    fn get(&self, name: &str) -> Result<Option<Account>, AccountsError>;

    /// Every account, by name.
    fn list(&self) -> Result<Vec<Account>, AccountsError>;

    /// How many accounts are held.
    fn count(&self) -> Result<usize, AccountsError>;

    /// The account holding `access_key`, and the key.
    fn by_access_key(
        &self,
        access_key: &str,
    ) -> Result<Option<(Account, AccessKey)>, AccountsError>;

    /// The revision `operation_id` produced and the account it named, when the store holds it:
    /// what recovery of the mutation journal reads.
    fn operation(&self, operation_id: &OperationId)
    -> Result<Option<(u64, String)>, AccountsError>;

    /// Writes the new account `account` at `now`, inside the operation `applying` names when
    /// one does; the offline commands and the first start write with none. No account of its
    /// name is held, or it is a [`AccountsError::Conflict`]. Answers the account as written.
    fn create(
        &self,
        applying: Option<&Applying<'_>>,
        account: Account,
        by: &str,
        now: u64,
    ) -> Result<Account, AccountsError>;

    /// Changes the account `name` at `now`: `change` is given the account as it stands and
    /// answers it as it shall be, or why not. The account `change` reads is the one its answer
    /// replaces: nothing changes the account between the two, so a change never undoes one it
    /// did not see, and what `change` refuses is refused of the account as it is. The name and
    /// the time it was made are the account's and are kept. Answers the account as written.
    ///
    /// `change` runs inside the store, while it holds the account: it decides from the account
    /// it is given and never calls the store, which would wait on itself.
    fn update(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        change: &dyn Fn(&Account) -> Result<Account, AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<Account, AccountsError>;

    /// Deletes the account `name`, its keys with it, once `allow` has seen it as it stands and
    /// let it go; `admin` is never deleted. `allow` runs inside the store, as the change of
    /// [`AccountStore::update`] does, and never calls it.
    fn delete(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        allow: &dyn Fn(&Account) -> Result<(), AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<(), AccountsError>;
}

/// The accounts, as recovery of the mutation journal sees them.
pub struct Recovering<'a>(pub &'a dyn AccountStore);

impl Domain for Recovering<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, _target: Option<&str>) -> Option<Observed> {
        match self.0.operation(operation_id) {
            Ok(found) => found.map(|(revision, name)| Observed {
                revision,
                target: Some(name),
            }),
            Err(error) => {
                // The engine reads `None` as not applied and records the operation failed, so
                // this answer is wrong for a store that could not be asked. No backend of this
                // build can fail here; the engine learns to stop instead with decision E17
                // (iteration 03, WP-26.2), before a backend that can fail exists.
                tracing::error!(
                    event.name = "authority.accounts.recovery_unreadable",
                    component = crate::COMPONENT,
                    reason = %error,
                    "the accounts could not say whether an operation was applied"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn the_administrators_scopes_are_coherent_and_reach_every_plane() {
        let scopes = admin_scopes();
        check_scopes(&scopes).expect("coherent");
        let reaches = |operation: &str, resource: &Resource| {
            scopes.iter().any(|scope| {
                scope.operations.contains(operation) && scope.selector.contains(resource)
            })
        };
        assert!(reaches(
            operations::ACCOUNTS_WRITE,
            &Resource::plane("authority")
        ));
        assert!(reaches(
            operations::DECISION_EVALUATE,
            &Resource::ledger("data", "z", "l")
        ));
        assert!(reaches(
            operations::CATALOG_WRITE,
            &Resource::zone("control", "z")
        ));
        assert!(reaches(operations::MEMBERSHIP_ADMIN, &Resource::host()));
        for operation in operations::ALL {
            assert!(
                scopes
                    .iter()
                    .any(|scope| scope.operations.contains(*operation)),
                "{operation}"
            );
        }
    }
}
