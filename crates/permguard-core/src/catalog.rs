// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Zones and the ledgers inside them: what they are, and the contract for keeping them.
//!
//! A **zone** is the isolation boundary — the tenant. A **ledger** is a named container inside a
//! zone; what a ledger *holds* is deliberately not decided here yet, so its record carries identity
//! and nothing else. Both are identified two ways, and the distinction is load-bearing:
//!
//! * the **id** is a GUID, minted by the store, permanent, and what other records should reference;
//! * the **name** is for people and command lines, unique in its scope — zone names across the
//!   deployment, ledger names within their zone — and free to change without anything dangling.
//!
//! # Why names are this strict
//!
//! `a-z`, `0-9`, `-` and `_`; a letter first, an alphanumeric last, three to sixty-three long.
//! Every one of those characters is unreserved in RFC 3986, so a name travels through a URL path,
//! a query string or a header with no encoding, ever — and what you read in a log is byte-for-byte
//! what was typed. Uppercase is refused rather than folded: a name that silently changes under
//! somebody's hands is worse than an error. A name shaped like a GUID is refused too, because
//! anything accepting "name or id" must never have to guess which one it was handed.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The shortest and longest a name may be.
const NAME_SHORTEST: usize = 3;
const NAME_LONGEST: usize = 63;

/// One zone, as every interface answers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    /// The permanent identity, a GUID minted at creation.
    pub id: String,
    /// The human name, unique across the deployment, free to change.
    pub name: String,
    /// When it was created, seconds since the Unix epoch.
    pub created_at: u64,
    /// When it last changed.
    pub updated_at: u64,
}

/// One ledger, inside one zone.
///
/// Identity only, on purpose: what a ledger holds is a design still being made, and a field shipped
/// now is a field to be compatible with forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// The permanent identity, a GUID minted at creation.
    pub id: String,
    /// The zone this ledger belongs to, by id.
    pub zone_id: String,
    /// The human name, unique within the zone.
    pub name: String,
    /// The ref this ledger considers its default line, `main` unless said
    /// otherwise. A reference, never a copy: the head digest lives only in
    /// the ledger's own `refs/<name>`, and anything showing a head reads it
    /// through the ref — one source of truth, no second head to drift.
    #[serde(default = "default_ref")]
    pub default_ref: String,
    /// When it was created, seconds since the Unix epoch.
    pub created_at: u64,
    /// When it last changed.
    pub updated_at: u64,
}

/// The ref a ledger starts life pointing at.
fn default_ref() -> String {
    "main".to_owned()
}

/// A zone or ledger as somebody referred to it: by id, or by name.
///
/// Parsing is what keeps "name or id" unambiguous: a GUID-shaped value is an id, everything else is
/// a name — and names shaped like GUIDs cannot be created, so the rule never guesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// Referred to by its GUID.
    Id(String),
    /// Referred to by its name.
    Name(String),
}

impl Selector {
    /// Reads a reference the way every interface does.
    pub fn parse(value: &str) -> Self {
        let value = value.trim();

        if is_guid_shaped(value) {
            Self::Id(value.to_ascii_lowercase())
        } else {
            Self::Name(value.to_owned())
        }
    }

    /// What was written, for an error message that quotes it back.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Id(value) | Self::Name(value) => value,
        }
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Checks that `name` is a name this catalog accepts, and says exactly what is wrong when not.
pub fn validate_name(name: &str) -> Result<(), CatalogError> {
    let refused = |detail: &str| {
        Err(CatalogError::InvalidName {
            name: name.to_owned(),
            detail: detail.to_owned(),
        })
    };

    if name.len() < NAME_SHORTEST || name.len() > NAME_LONGEST {
        return refused(&format!(
            "it must be between {NAME_SHORTEST} and {NAME_LONGEST} characters"
        ));
    }

    if !name.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    }) {
        // Named precisely: the most common mistake is an uppercase letter, and "invalid character"
        // sends someone hunting for a symbol that is not there.
        if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return refused("uppercase is refused rather than converted: use lowercase");
        }

        return refused("only a-z, 0-9, `-` and `_` are accepted");
    }

    if !name.as_bytes()[0].is_ascii_lowercase() {
        return refused("it must start with a letter");
    }

    let last = name.as_bytes()[name.len() - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return refused("it must end with a letter or a digit");
    }

    if is_guid_shaped(name) {
        return refused("it is shaped like an id, and a name must never be mistakable for one");
    }

    Ok(())
}

/// Whether `value` has the 8-4-4-4-12 hexadecimal shape of a GUID.
pub fn is_guid_shaped(value: &str) -> bool {
    let bytes = value.as_bytes();

    if bytes.len() != 36 {
        return false;
    }

    bytes.iter().enumerate().all(|(at, byte)| match at {
        8 | 13 | 18 | 23 => *byte == b'-',
        _ => byte.is_ascii_hexdigit(),
    })
}

/// The contract for keeping zones and ledgers.
///
/// Synchronous on purpose: every operation is a handful of small files, and the callers that need
/// async wrap it the way they wrap every other blocking collaborator. Implementations must make
/// each method atomic against concurrent callers — creating two zones with one name from two
/// threads must fail for exactly one of them.
pub trait Catalog: Send + Sync {
    /// Names the implementation, for records.
    fn name(&self) -> &'static str;

    /// Creates a zone. Fails with [`CatalogError::NameTaken`] when the name exists.
    fn create_zone(&self, name: &str) -> Result<Zone, CatalogError>;

    /// Lists every zone, ordered by creation.
    fn list_zones(&self) -> Result<Vec<Zone>, CatalogError>;

    /// Returns the zone a selector refers to.
    fn get_zone(&self, zone: &Selector) -> Result<Zone, CatalogError>;

    /// Renames a zone. The id never changes; that is what it is for.
    fn rename_zone(&self, zone: &Selector, name: &str) -> Result<Zone, CatalogError>;

    /// Deletes a zone. Fails with [`CatalogError::NotEmpty`] while it still holds ledgers:
    /// deleting a tenant's containers should never be a side effect of a one-line command.
    fn delete_zone(&self, zone: &Selector) -> Result<Zone, CatalogError>;

    /// Creates a ledger inside a zone.
    fn create_ledger(&self, zone: &Selector, name: &str) -> Result<Ledger, CatalogError>;

    /// Lists a zone's ledgers, ordered by creation.
    fn list_ledgers(&self, zone: &Selector) -> Result<Vec<Ledger>, CatalogError>;

    /// Returns the ledger a selector refers to, inside a zone.
    fn get_ledger(&self, zone: &Selector, ledger: &Selector) -> Result<Ledger, CatalogError>;

    /// Renames a ledger within its zone.
    fn rename_ledger(
        &self,
        zone: &Selector,
        ledger: &Selector,
        name: &str,
    ) -> Result<Ledger, CatalogError>;

    /// Deletes a ledger.
    fn delete_ledger(&self, zone: &Selector, ledger: &Selector) -> Result<Ledger, CatalogError>;
}

/// Every way the catalog can refuse, each one an answer a caller can act on.
#[derive(Debug)]
pub enum CatalogError {
    /// The name is already someone else's, in the scope where names are unique.
    NameTaken { name: String, scope: String },
    /// Nothing answers to this reference.
    NotFound {
        kind: &'static str,
        selector: String,
    },
    /// The zone still holds ledgers, and deleting them must be asked for one by one.
    NotEmpty { zone: String, ledgers: usize },
    /// The name breaks the rules names keep.
    InvalidName { name: String, detail: String },
    /// The store itself failed.
    Backend { detail: String },
}

impl CatalogError {
    /// Builds a backend failure from anything that can describe itself.
    pub fn backend(detail: impl fmt::Display) -> Self {
        Self::Backend {
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameTaken { name, scope } => {
                write!(f, "the name `{name}` is already taken in {scope}")
            }
            Self::NotFound { kind, selector } => {
                write!(f, "no {kind} answers to `{selector}`")
            }
            Self::NotEmpty { zone, ledgers } => write!(
                f,
                "the zone `{zone}` still holds {ledgers} ledger(s): delete them first"
            ),
            Self::InvalidName { name, detail } => {
                write!(f, "`{name}` is not a name this catalog accepts: {detail}")
            }
            Self::Backend { detail } => write!(f, "the catalog store failed: {detail}"),
        }
    }
}

impl std::error::Error for CatalogError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_what_a_name_may_be() {
        for good in ["abc", "pharma-authz", "zone_2", "a1", "a-b_c9"] {
            if good.len() >= NAME_SHORTEST {
                assert!(validate_name(good).is_ok(), "refused {good:?}");
            }
        }

        for (bad, why) in [
            ("ab", "too short"),
            (&"a".repeat(64), "too long"),
            ("Pharma", "uppercase"),
            ("has space", "space"),
            ("caffè", "non-ascii"),
            ("-abc", "starts with dash"),
            ("1abc", "starts with digit"),
            ("abc-", "ends with dash"),
            ("abc_", "ends with underscore"),
            ("a.b.c", "dot"),
            ("a/b", "slash"),
            ("00000000-0000-7000-8000-000000000000", "guid-shaped"),
        ] {
            assert!(validate_name(bad).is_err(), "accepted {why}: {bad:?}");
        }
    }

    #[test]
    fn test_a_reference_is_an_id_or_a_name_and_never_a_guess() {
        assert_eq!(
            Selector::parse("0198f2a0-1234-7abc-8def-0123456789ab"),
            Selector::Id("0198f2a0-1234-7abc-8def-0123456789ab".to_owned())
        );
        // Ids are compared case-insensitively by lowering at the door.
        assert_eq!(
            Selector::parse("0198F2A0-1234-7ABC-8DEF-0123456789AB"),
            Selector::Id("0198f2a0-1234-7abc-8def-0123456789ab".to_owned())
        );
        assert_eq!(
            Selector::parse("pharma-authz"),
            Selector::Name("pharma-authz".to_owned())
        );
        // 36 characters but not hex in the right places: a name.
        assert_eq!(
            Selector::parse("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
            Selector::Name("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz".to_owned())
        );
    }
}
