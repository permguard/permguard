// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The tokens the Authority Plane issued and the status lists they are read in (`2-security/9`
//! The list), and the contract their store keeps (`1-architecture/8` Store contracts).
//!
//! | Here             | What                                                                       |
//! | ---------------- | -------------------------------------------------------------------------- |
//! | [`IssuedToken`]  | one token the store holds: its `jti`, its list entry, its status           |
//! | [`ListView`]     | a list as it stands: what a status list token signs                        |
//! | [`TokenStore`]   | the contract: every way the Authority Plane records and revokes its tokens |
//! | [`files`]        | the file backend: one journal on the volume                                |
//! | [`postgres`]     | the PostgreSQL backend: a row a token and a row a list                     |
//! | [`suite`]        | the conformance suite every backend of the contract passes                 |
//!
//! | Rule of the contract                                   | Where                                |
//! | ------------------------------------------------------ | ------------------------------------ |
//! | a token expires after it is issued and carries a scope | [`TokenStore::issue`]                |
//! | an entry is drawn at random among the free ones of the open list, and never drawn again in that list | [`TokenStore::issue`] |
//! | a list is open until [`OPEN_UNTIL`] of its entries are drawn | [`TokenStore::issue`]          |
//! | `INVALID` is terminal                                  | [`TokenStore::set_status`]           |
//! | a token is revocable until a clock skew past its expiry | [`TokenStore::set_status`]          |
//! | a list retires once every token it holds has expired, the open one never, and its tokens are forgotten with it | [`TokenStore::retire_expired`] |
//! | the revision rises with every change, never otherwise  | [`TokenStore::revision`]             |

use permguard_core::authz::TokenScope;
use permguard_host::identity::record::uuid_text;
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::{Applying, Domain, Observed};
use permguard_objects::status_list::{ENTRIES, StatusList};

pub mod files;
pub mod postgres;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

/// The bits per entry of every list.
pub const BITS: u8 = permguard_host::authz::status_lists::BITS;
/// A list stays open until half its entries are drawn: a draw at random then takes two tries on
/// average.
pub const OPEN_UNTIL: usize = ENTRIES / 2;
/// The domain token revocations run in.
pub const DOMAIN: &str = "authority.tokens";

/// The entry values (`2-security/9` The list).
pub mod status {
    pub const VALID: u8 = 0;
    /// Terminal.
    pub const INVALID: u8 = 1;
    pub const SUSPENDED: u8 = 2;

    /// The value's name, as the API answers it.
    pub fn name(value: u8) -> &'static str {
        match value {
            VALID => "valid",
            INVALID => "invalid",
            SUSPENDED => "suspended",
            _ => "unknown",
        }
    }

    /// The value a name answers to.
    pub fn parse(name: &str) -> Option<u8> {
        match name {
            "valid" => Some(VALID),
            "invalid" => Some(INVALID),
            "suspended" => Some(SUSPENDED),
            _ => None,
        }
    }
}

/// The id `text` names, as a UUID's text.
pub fn parse_id(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || text.len() != 36 {
        return None;
    }
    let mut id = [0u8; 16];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    (uuid_text(&id) == text.to_ascii_lowercase()).then_some(id)
}

/// What a store refuses, and what it could not do.
#[derive(Debug)]
pub enum TokenError {
    Invalid(String),
    NotFound(String),
    Random,
    /// The store did not answer, or what it holds does not read: nothing is known of the change.
    Unavailable(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) | Self::NotFound(detail) | Self::Unavailable(detail) => {
                f.write_str(detail)
            }
            Self::Random => f.write_str("the system's random generator failed"),
        }
    }
}

impl std::error::Error for TokenError {}

/// What a token is issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenDraft {
    pub account: String,
    pub access_key: String,
    pub scopes: Vec<TokenScope>,
    pub expires_at: u64,
}

/// One token the registry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    pub jti: [u8; 16],
    pub list_id: [u8; 16],
    pub index: u64,
    pub account: String,
    pub access_key: String,
    pub scopes: Vec<TokenScope>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: u8,
}

impl IssuedToken {
    /// Its id, as a UUID.
    pub fn jti_text(&self) -> String {
        uuid_text(&self.jti)
    }
}

/// A list as it stands: what a status list token signs.
#[derive(Debug, Clone)]
pub struct ListView {
    pub list_id: [u8; 16],
    pub list: StatusList,
    /// The registry revision of its last change.
    pub changed_at: u64,
}

/// The tokens of one Authority Plane and their lists: the only way its code records, reads and
/// revokes them.
///
/// A call holds one complete rule: what it checks and what it writes are never two calls a
/// caller could interleave. A read answers what a committed transition left.
pub trait TokenStore: Send + Sync + std::fmt::Debug {
    /// A number that rises with every change and never otherwise: a token issued, a status
    /// changed, a list retired. How many it rises by is the backend's.
    fn revision(&self) -> Result<u64, TokenError>;

    /// Records a token for `draft`, issued at `now`: its `jti` and the list entry its status is
    /// read from. The list is opened, when needed, in the same change.
    fn issue(&self, draft: TokenDraft, now: u64) -> Result<IssuedToken, TokenError>;

    /// Sets the status of every live token `matches` selects, at `now`, inside the operation
    /// `applying` names when one does: an `INVALID` token stays so. Answers how many changed.
    fn set_status(
        &self,
        applying: Option<&Applying<'_>>,
        matches: &dyn Fn(&IssuedToken) -> bool,
        value: u8,
        by: &str,
        now: u64,
    ) -> Result<usize, TokenError>;

    /// Retires every list but the open one whose tokens have all expired at `now`, forgetting
    /// them. Answers the lists retired.
    fn retire_expired(&self, by: &str, now: u64) -> Result<usize, TokenError>;

    /// The token `jti` names, while the store holds it.
    fn token(&self, jti: &[u8; 16]) -> Result<Option<IssuedToken>, TokenError>;

    /// Every token not yet expired at `now`, newest first.
    fn live_tokens(&self, now: u64) -> Result<Vec<IssuedToken>, TokenError>;

    /// When `access_key` last obtained a token the store still holds.
    fn last_used(&self, access_key: &str) -> Result<Option<u64>, TokenError>;

    /// The list `list_id` names, as it stands.
    fn list(&self, list_id: &[u8; 16]) -> Result<Option<ListView>, TokenError>;

    /// Every list's id.
    fn list_ids(&self) -> Result<Vec<[u8; 16]>, TokenError>;

    /// The revision of `list_id`'s last change, without its entries.
    fn changed_at(&self, list_id: &[u8; 16]) -> Result<Option<u64>, TokenError>;

    /// The revision `operation_id` produced and what it named, when the store holds it: what
    /// recovery of the mutation journal reads.
    fn operation(&self, operation_id: &OperationId) -> Result<Option<(u64, String)>, TokenError>;
}

/// The tokens, as recovery of the mutation journal sees them.
pub struct Recovering<'a>(pub &'a dyn TokenStore);

impl Domain for Recovering<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(
        &self,
        operation_id: &OperationId,
        _target: Option<&str>,
    ) -> Result<Option<Observed>, String> {
        // A store that cannot be asked stops the recovery: the engine never records as failed an
        // operation its domain may have applied (decision E17).
        Ok(self
            .0
            .operation(operation_id)
            .map_err(|error| error.to_string())?
            .map(|(revision, named)| Observed {
                revision,
                target: Some(named),
            }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn ids_read_as_uuids() {
        let text = uuid_text(&[0xab; 16]);
        assert_eq!(parse_id(&text), Some([0xab; 16]));
        assert_eq!(parse_id("../x"), None);
        assert_eq!(parse_id(&text.replace('-', "")), None);
    }
}
