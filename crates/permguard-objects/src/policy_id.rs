// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The policy identity cascade — a pure function of (previous tree, content),
//! computed by the client and recomputed by the server for verification.
//! Never random, never minted per push, and **never authored**: the identity
//! is always the system's. What the author may declare is an *alias* — an
//! optional human handle that carries the identity across renames, never the
//! id itself.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

/// The domain-separation prefix of rule 3: 22 ASCII bytes, no separator.
const DOMAIN_PREFIX: &[u8] = b"permguard.policy.id.v1";

/// Derive the content-derived identity of rule 3: SHA-256 over the
/// domain-separation prefix followed by the verbatim authored bytes, folded
/// to a UUID exactly as the specification defines — bytes 0–15 in order,
/// byte 6 forced to version 8, byte 8 forced to the RFC 9562 variant,
/// rendered lowercase hyphenated 8-4-4-4-12.
/// The well-known annotation keys a tree entry carries for a policy: the
/// identity, the author's alias, and the kind. Names in the model, because a
/// tree entry is the model's — what fills them is somebody else's business.
pub const ANNOTATION_POLICY_ID: &str = "permguard.policy.id";
pub const ANNOTATION_POLICY_ALIAS: &str = "permguard.policy.alias";
pub const ANNOTATION_POLICY_KIND: &str = "permguard.policy.kind";

/// The media-type family that marks a blob as a policy, and therefore as
/// something that must carry identity annotations. A prefix, not a
/// catalogue: the model recognises the *family*, never the languages in it.
pub const POLICY_FAMILY_PREFIX: &str = "application/vnd.permguard.policy.";

pub fn derive_policy_id(authored_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PREFIX);
    hasher.update(authored_bytes);
    let digest = hasher.finalize();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    render_uuid(&uuid)
}

fn render_uuid(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The outcome of the cascade for one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedId {
    /// Rule 1: carried forward from the previous tree by logical path.
    CarriedByPath(String),
    /// Rule 2: carried forward matched by alias, when no path matched — the
    /// rename case.
    CarriedByAlias(String),
    /// Rule 3: derived from the authored bytes — a new entry.
    Derived(String),
}

impl ResolvedId {
    pub fn id(&self) -> &str {
        match self {
            ResolvedId::CarriedByPath(id)
            | ResolvedId::CarriedByAlias(id)
            | ResolvedId::Derived(id) => id,
        }
    }
}

/// Why the cascade rejected an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyIdError {
    /// Two parents disagree on the identity of the same logical path or alias.
    MergeConflict {
        path: String,
        left: String,
        right: String,
    },
    /// The same id appears on two entries of one snapshot.
    DuplicateId { id: String },
    /// The same alias appears on two entries of one snapshot.
    DuplicateAlias { alias: String },
}

impl std::fmt::Display for PolicyIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyIdError::MergeConflict { path, left, right } => write!(
                f,
                "merge parents disagree on the identity of {path}: {left} vs {right}"
            ),
            PolicyIdError::DuplicateId { id } => {
                write!(f, "policy id {id} appears more than once in the snapshot")
            }
            PolicyIdError::DuplicateAlias { alias } => {
                write!(
                    f,
                    "policy alias {alias} appears more than once in the snapshot"
                )
            }
        }
    }
}

impl std::error::Error for PolicyIdError {}

/// Resolve the id of one entry through the cascade.
///
/// `previous_by_path` are the ids the same logical path carries in the
/// predecessor tree(s); `previous_by_alias` are the ids entries carrying the
/// same alias hold there — consulted only when no path matches (the rename
/// case). Each holds zero entries for no match, one for a linear edit, up to
/// two for a merge.
pub fn resolve_id(
    path: &str,
    previous_by_path: &[&str],
    previous_by_alias: &[&str],
    authored_bytes: &[u8],
) -> Result<ResolvedId, PolicyIdError> {
    let carried = |previous: &[&str]| -> Result<Option<String>, PolicyIdError> {
        // A merge whose parents disagree is a conflict: the client must
        // resolve which identity survives, explicitly.
        if previous.len() == 2 && previous[0] != previous[1] {
            return Err(PolicyIdError::MergeConflict {
                path: path.to_string(),
                left: previous[0].to_string(),
                right: previous[1].to_string(),
            });
        }
        Ok(previous.first().map(|id| (*id).to_string()))
    };

    if let Some(id) = carried(previous_by_path)? {
        return Ok(ResolvedId::CarriedByPath(id));
    }
    if let Some(id) = carried(previous_by_alias)? {
        return Ok(ResolvedId::CarriedByAlias(id));
    }
    Ok(ResolvedId::Derived(derive_policy_id(authored_bytes)))
}

/// Enforce snapshot-level uniqueness: every policy id at most once.
pub fn check_uniqueness<'a, I>(ids: I) -> Result<(), PolicyIdError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for id in ids {
        if seen.insert(id, ()).is_some() {
            return Err(PolicyIdError::DuplicateId { id: id.to_string() });
        }
    }
    Ok(())
}

/// Enforce snapshot-level alias uniqueness: every alias at most once.
pub fn check_alias_uniqueness<'a, I>(aliases: I) -> Result<(), PolicyIdError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for alias in aliases {
        if seen.insert(alias, ()).is_some() {
            return Err(PolicyIdError::DuplicateAlias {
                alias: alias.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_uuid_shaped() {
        let a = derive_policy_id(b"permit(principal, action, resource);");
        let b = derive_policy_id(b"permit(principal, action, resource);");
        assert_eq!(a, b);
        assert_eq!(a.len(), 36);
        let parts: Vec<&str> = a.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        // Version nibble is 8, variant bits are 10xx.
        assert_eq!(&parts[2][..1], "8");
        assert!(matches!(&parts[3][..1], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn different_bytes_different_id() {
        assert_ne!(derive_policy_id(b"a"), derive_policy_id(b"b"));
    }

    #[test]
    fn cascade_rules() {
        // New entry, nothing matches -> derived.
        let derived = resolve_id("p.cedar", &[], &[], b"src").unwrap();
        assert!(matches!(derived, ResolvedId::Derived(_)));
        // Edit: the path carries, whatever the bytes.
        assert_eq!(
            resolve_id("p.cedar", &["id-1"], &[], b"changed").unwrap(),
            ResolvedId::CarriedByPath("id-1".into())
        );
        // Rename with an alias: no path match, the alias carries.
        assert_eq!(
            resolve_id("renamed.cedar", &[], &["id-1"], b"same bytes").unwrap(),
            ResolvedId::CarriedByAlias("id-1".into())
        );
        // The path wins over the alias when both match.
        assert_eq!(
            resolve_id("p.cedar", &["id-1"], &["id-2"], b"x").unwrap(),
            ResolvedId::CarriedByPath("id-1".into())
        );
        // Merge parents disagreeing -> conflict, on either hook.
        assert!(matches!(
            resolve_id("p.cedar", &["id-1", "id-2"], &[], b"x"),
            Err(PolicyIdError::MergeConflict { .. })
        ));
        assert!(matches!(
            resolve_id("p.cedar", &[], &["id-1", "id-2"], b"x"),
            Err(PolicyIdError::MergeConflict { .. })
        ));
        // Merge parents agreeing -> carried.
        assert_eq!(
            resolve_id("p.cedar", &["id-1", "id-1"], &[], b"x").unwrap(),
            ResolvedId::CarriedByPath("id-1".into())
        );
    }

    #[test]
    fn uniqueness() {
        assert!(check_uniqueness(["a", "b"]).is_ok());
        assert!(matches!(
            check_uniqueness(["a", "a"]),
            Err(PolicyIdError::DuplicateId { .. })
        ));
        assert!(check_alias_uniqueness(["x", "y"]).is_ok());
        assert!(matches!(
            check_alias_uniqueness(["x", "x"]),
            Err(PolicyIdError::DuplicateAlias { .. })
        ));
    }
}
