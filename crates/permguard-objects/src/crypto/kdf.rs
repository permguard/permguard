// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! HKDF-SHA-256 (RFC 5869) with `info` as a deterministic-CBOR tuple.
//!
//! A derived key is only as separate as its `info`. Two purposes whose `info` strings can collide —
//! `"audit" || "pseudonym"` against `"auditpseudo" || "nym"` — share a key without anybody having
//! decided they should. The blueprint therefore forbids string concatenation: every `info` is a
//! CBOR array with fixed positions and typed members, so a purpose, a resource and a version can
//! never run into each other, and an implementation in another language encodes the same tuple to
//! the same bytes.
//!
//! Three derivations exist, with three different salts and label words, and they do not share a
//! helper that could inject the local Host id by accident:
//!
//! ```text
//! host_local_key  = HKDF(host_root,        salt = owner_host_id,     info = [label, "host-local", purpose, authority_host_id, resource, key_version])
//! zone_root       = HKDF(coordinator_root, salt = authority_host_id, info = [label, "zone-root",  zone_id, version])
//! distributed_key = HKDF(zone_root,        salt = authority_host_id, info = [label, "zone-use",   purpose, zone_id, scope, version])
//! ```
//!
//! The local member's `host_id` is absent from the last two on purpose: every authorised replica of
//! a zone must compute the same value.

use std::fmt;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use zeroize::{Zeroize as _, Zeroizing};

use crate::cbor::{self, Value};
use permguard_core::domains::kdf as labels;

/// The shortest root this profile accepts: 256 random bits.
pub const MIN_ROOT_LEN: usize = 32;

/// The length of every derived key.
pub const KEY_LEN: usize = 32;

/// A Host, zone or ledger identifier as its 16 UUID bytes.
pub type Id = [u8; 16];

/// Why a derivation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// The root is shorter than 256 bits.
    RootTooShort { length: usize },
    /// More output was asked for than HKDF-SHA-256 can produce (255 × 32 bytes).
    OutputTooLong { length: usize },
    /// The version does not fit the integer model of the canonical encoding.
    VersionRange(u64),
    /// The bytes are not an `info` tuple of this profile.
    Encoding(&'static str),
    /// The MAC refused a key; HMAC accepts any key length, so this is unreachable by construction
    /// and exists only so that no path returns bytes it did not derive.
    Internal,
}

impl fmt::Display for KdfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootTooShort { length } => write!(
                formatter,
                "a {length}-byte root is shorter than the {MIN_ROOT_LEN} bytes this profile requires"
            ),
            Self::OutputTooLong { length } => {
                write!(
                    formatter,
                    "{length} bytes exceed what HKDF-SHA-256 can derive"
                )
            }
            Self::VersionRange(version) => {
                write!(formatter, "the version {version} cannot be encoded")
            }
            Self::Encoding(detail) => write!(formatter, "not a KDF info tuple: {detail}"),
            Self::Internal => formatter.write_str("the MAC refused the key"),
        }
    }
}

impl std::error::Error for KdfError {}

type HmacSha256 = Hmac<Sha256>;

/// HKDF-SHA-256 extract-then-expand into `out`.
///
/// An empty `salt` is the specification's zero salt. The root is not checked here, because this is
/// the raw function the vectors exercise; the derivations below enforce [`MIN_ROOT_LEN`].
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), KdfError> {
    if out.len() > 255 * 32 {
        return Err(KdfError::OutputTooLong { length: out.len() });
    }
    let zero_salt = [0u8; 32];
    let salt = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };

    let mut prk = Zeroizing::new([0u8; 32]);
    {
        let mut extract = HmacSha256::new_from_slice(salt).map_err(|_| KdfError::Internal)?;
        extract.update(ikm);
        let mut block = extract.finalize().into_bytes();
        prk.copy_from_slice(&block[..]);
        block[..].zeroize();
    }

    let mut previous = Zeroizing::new(Vec::new());
    let mut filled = 0usize;
    let mut counter = 1u8;
    while filled < out.len() {
        let mut expand = HmacSha256::new_from_slice(&prk[..]).map_err(|_| KdfError::Internal)?;
        expand.update(&previous);
        expand.update(info);
        expand.update(&[counter]);
        let mut block = expand.finalize().into_bytes();
        let take = (out.len() - filled).min(32);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        previous.clear();
        previous.extend_from_slice(&block[..]);
        block[..].zeroize();
        filled += take;
        counter = counter.wrapping_add(1);
    }

    Ok(())
}

/// One `info` tuple: a closed CBOR array whose positions and member types are fixed.
///
/// Labels and purposes are text, Host, zone and scope identifiers their 16 UUID bytes, `resource`
/// the canonical resource text, versions unsigned integers. [`Info::decode`] refuses another
/// length, another label or another member type rather than coercing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Info {
    /// `["permguard.kdf.v1", "host-local", purpose, authority_host_id, resource, key_version]`.
    HostLocal {
        purpose: String,
        authority_host_id: Id,
        resource: String,
        key_version: u64,
    },
    /// `["permguard.kdf.v1", "zone-root", zone_id, version]`.
    ZoneRoot { zone_id: Id, version: u64 },
    /// `["permguard.kdf.v1", "zone-use", purpose, zone_id, scope, version]`.
    ZoneUse {
        purpose: String,
        zone_id: Id,
        scope: Id,
        version: u64,
    },
}

impl Info {
    /// The deterministic-CBOR bytes HKDF receives as `info`.
    pub fn encode(&self) -> Result<Vec<u8>, KdfError> {
        let members = match self {
            Self::HostLocal {
                purpose,
                authority_host_id,
                resource,
                key_version,
            } => vec![
                Value::Text(labels::LABEL.to_owned()),
                Value::Text(labels::HOST_LOCAL.to_owned()),
                Value::Text(purpose.clone()),
                Value::Bytes(authority_host_id.to_vec()),
                Value::Text(resource.clone()),
                version(*key_version)?,
            ],
            Self::ZoneRoot {
                zone_id,
                version: v,
            } => vec![
                Value::Text(labels::LABEL.to_owned()),
                Value::Text(labels::ZONE_ROOT.to_owned()),
                Value::Bytes(zone_id.to_vec()),
                version(*v)?,
            ],
            Self::ZoneUse {
                purpose,
                zone_id,
                scope,
                version: v,
            } => vec![
                Value::Text(labels::LABEL.to_owned()),
                Value::Text(labels::ZONE_USE.to_owned()),
                Value::Text(purpose.clone()),
                Value::Bytes(zone_id.to_vec()),
                Value::Bytes(scope.to_vec()),
                version(*v)?,
            ],
        };

        Ok(cbor::encode(&Value::Array(members)))
    }

    /// Reads an `info` tuple strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, KdfError> {
        let Ok(Value::Array(members)) = cbor::decode_canonical(bytes) else {
            return Err(KdfError::Encoding(
                "an info tuple is one canonical CBOR array",
            ));
        };
        let [Value::Text(label), Value::Text(kind), rest @ ..] = members.as_slice() else {
            return Err(KdfError::Encoding(
                "an info tuple opens with two text labels",
            ));
        };
        if label != labels::LABEL {
            return Err(KdfError::Encoding(
                "the first member is not `permguard.kdf.v1`",
            ));
        }
        match (kind.as_str(), rest) {
            (
                labels::HOST_LOCAL,
                [
                    Value::Text(purpose),
                    Value::Bytes(authority),
                    Value::Text(resource),
                    Value::Int(key_version),
                ],
            ) => Ok(Self::HostLocal {
                purpose: purpose.clone(),
                authority_host_id: uuid(authority)?,
                resource: resource.clone(),
                key_version: unsigned(*key_version)?,
            }),
            (labels::ZONE_ROOT, [Value::Bytes(zone), Value::Int(v)]) => Ok(Self::ZoneRoot {
                zone_id: uuid(zone)?,
                version: unsigned(*v)?,
            }),
            (
                labels::ZONE_USE,
                [
                    Value::Text(purpose),
                    Value::Bytes(zone),
                    Value::Bytes(scope),
                    Value::Int(v),
                ],
            ) => Ok(Self::ZoneUse {
                purpose: purpose.clone(),
                zone_id: uuid(zone)?,
                scope: uuid(scope)?,
                version: unsigned(*v)?,
            }),
            (labels::HOST_LOCAL | labels::ZONE_ROOT | labels::ZONE_USE, _) => Err(
                KdfError::Encoding("the tuple has another length or member type than its kind"),
            ),
            _ => Err(KdfError::Encoding(
                "the second member is not a derivation kind",
            )),
        }
    }
}

fn uuid(bytes: &[u8]) -> Result<Id, KdfError> {
    bytes
        .try_into()
        .map_err(|_| KdfError::Encoding("an identifier is exactly 16 UUID bytes"))
}

fn unsigned(value: i64) -> Result<u64, KdfError> {
    u64::try_from(value).map_err(|_| KdfError::Encoding("a version is an unsigned integer"))
}

/// The `info` of a Host-local key.
pub fn host_local_info(
    purpose: &str,
    authority_host_id: &Id,
    resource: &str,
    key_version: u64,
) -> Result<Vec<u8>, KdfError> {
    Info::HostLocal {
        purpose: purpose.to_owned(),
        authority_host_id: *authority_host_id,
        resource: resource.to_owned(),
        key_version,
    }
    .encode()
}

/// The `info` of a zone root.
pub fn zone_root_info(zone_id: &Id, zone_version: u64) -> Result<Vec<u8>, KdfError> {
    Info::ZoneRoot {
        zone_id: *zone_id,
        version: zone_version,
    }
    .encode()
}

/// The `info` of a distributed per-purpose, per-scope key.
pub fn zone_use_info(
    purpose: &str,
    zone_id: &Id,
    scope: &Id,
    zone_version: u64,
) -> Result<Vec<u8>, KdfError> {
    Info::ZoneUse {
        purpose: purpose.to_owned(),
        zone_id: *zone_id,
        scope: *scope,
        version: zone_version,
    }
    .encode()
}

fn version(value: u64) -> Result<Value, KdfError> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| KdfError::VersionRange(value))
}

/// A key derived from a Host-local root, bound to a purpose, an authority, a resource and a version.
pub fn derive_host_local(
    host_root: &[u8],
    owner_host_id: &Id,
    purpose: &str,
    authority_host_id: &Id,
    resource: &str,
    key_version: u64,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    let info = host_local_info(purpose, authority_host_id, resource, key_version)?;
    derive(host_root, owner_host_id, &info)
}

/// The root of one zone at one version, held by the coordinator and never delivered.
pub fn derive_zone_root(
    coordinator_root: &[u8],
    authority_host_id: &Id,
    zone_id: &Id,
    zone_version: u64,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    let info = zone_root_info(zone_id, zone_version)?;
    derive(coordinator_root, authority_host_id, &info)
}

/// The key every authorised replica of a zone receives for one purpose and scope.
pub fn derive_distributed_key(
    zone_root: &[u8],
    authority_host_id: &Id,
    purpose: &str,
    zone_id: &Id,
    scope: &Id,
    zone_version: u64,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    let info = zone_use_info(purpose, zone_id, scope, zone_version)?;
    derive(zone_root, authority_host_id, &info)
}

fn derive(root: &[u8], salt: &Id, info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    if root.len() < MIN_ROOT_LEN {
        return Err(KdfError::RootTooShort { length: root.len() });
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf_sha256(salt, root, info, &mut out[..])?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [0x42; 32];
    const HOST_A: Id = [1; 16];
    const HOST_B: Id = [2; 16];
    const ZONE: Id = [3; 16];
    const LEDGER: Id = [4; 16];

    #[test]
    fn test_a_short_root_is_refused_before_anything_is_derived() {
        assert_eq!(
            derive_zone_root(&[0u8; 16], &HOST_A, &ZONE, 1),
            Err(KdfError::RootTooShort { length: 16 })
        );
    }

    #[test]
    fn test_every_tuple_member_separates_keys() {
        let base = derive_host_local(&ROOT, &HOST_A, "audit.pseudonym", &HOST_A, "r", 1).unwrap();
        let variants = [
            derive_host_local(&ROOT, &HOST_B, "audit.pseudonym", &HOST_A, "r", 1).unwrap(),
            derive_host_local(&ROOT, &HOST_A, "decision.commitment", &HOST_A, "r", 1).unwrap(),
            derive_host_local(&ROOT, &HOST_A, "audit.pseudonym", &HOST_B, "r", 1).unwrap(),
            derive_host_local(&ROOT, &HOST_A, "audit.pseudonym", &HOST_A, "s", 1).unwrap(),
            derive_host_local(&ROOT, &HOST_A, "audit.pseudonym", &HOST_A, "r", 2).unwrap(),
        ];
        for variant in &variants {
            assert_ne!(**variant, *base);
        }
    }

    #[test]
    fn test_distributed_keys_do_not_depend_on_the_member_and_do_separate_scopes() {
        let root = derive_zone_root(&ROOT, &HOST_A, &ZONE, 1).unwrap();
        let on_member_one =
            derive_distributed_key(&root[..], &HOST_A, "decision.commitment", &ZONE, &LEDGER, 1)
                .unwrap();
        let on_member_two =
            derive_distributed_key(&root[..], &HOST_A, "decision.commitment", &ZONE, &LEDGER, 1)
                .unwrap();
        let other_scope =
            derive_distributed_key(&root[..], &HOST_A, "decision.commitment", &ZONE, &ZONE, 1)
                .unwrap();

        assert_eq!(*on_member_one, *on_member_two);
        assert_ne!(*on_member_one, *other_scope);
        // A purpose and a resource that would collide under concatenation do not collide here.
        let info_a = host_local_info("ab", &HOST_A, "c", 1).unwrap();
        let info_b = host_local_info("a", &HOST_A, "bc", 1).unwrap();
        assert_ne!(info_a, info_b);
    }

    #[test]
    fn test_every_info_tuple_decodes_back_and_nothing_else_decodes() {
        for info in [
            Info::HostLocal {
                purpose: "audit.pseudonym".into(),
                authority_host_id: HOST_A,
                resource: "plane/data/zone/x".into(),
                key_version: 1,
            },
            Info::ZoneRoot {
                zone_id: ZONE,
                version: 7,
            },
            Info::ZoneUse {
                purpose: "decision.commitment".into(),
                zone_id: ZONE,
                scope: LEDGER,
                version: 2,
            },
        ] {
            assert_eq!(Info::decode(&info.encode().unwrap()).unwrap(), info);
        }

        let text = |value: &str| Value::Text(value.to_owned());
        let id = |value: Id| Value::Bytes(value.to_vec());
        let refused = [
            ("not an array", Value::Text("x".into())),
            (
                "another label",
                Value::Array(vec![
                    text("permguard.kdf.v2"),
                    text("zone-root"),
                    id(ZONE),
                    Value::Int(1),
                ]),
            ),
            (
                "an unknown kind",
                Value::Array(vec![
                    text(labels::LABEL),
                    text("zone-other"),
                    id(ZONE),
                    Value::Int(1),
                ]),
            ),
            (
                "one member short",
                Value::Array(vec![text(labels::LABEL), text(labels::ZONE_ROOT), id(ZONE)]),
            ),
            (
                "one member too many",
                Value::Array(vec![
                    text(labels::LABEL),
                    text(labels::ZONE_ROOT),
                    id(ZONE),
                    Value::Int(1),
                    Value::Int(1),
                ]),
            ),
            (
                "an identifier as text",
                Value::Array(vec![
                    text(labels::LABEL),
                    text(labels::ZONE_ROOT),
                    text("zone"),
                    Value::Int(1),
                ]),
            ),
            (
                "a short identifier",
                Value::Array(vec![
                    text(labels::LABEL),
                    text(labels::ZONE_ROOT),
                    Value::Bytes(vec![3; 15]),
                    Value::Int(1),
                ]),
            ),
            (
                "a negative version",
                Value::Array(vec![
                    text(labels::LABEL),
                    text(labels::ZONE_ROOT),
                    id(ZONE),
                    Value::Int(-1),
                ]),
            ),
            (
                "a version as text",
                Value::Array(vec![
                    text(labels::LABEL),
                    text(labels::ZONE_ROOT),
                    id(ZONE),
                    text("1"),
                ]),
            ),
            (
                "a purpose as bytes",
                Value::Array(vec![
                    text(labels::LABEL),
                    text(labels::ZONE_USE),
                    Value::Bytes(b"decision.commitment".to_vec()),
                    id(ZONE),
                    id(LEDGER),
                    Value::Int(1),
                ]),
            ),
            (
                "host-local members in zone-use positions",
                Value::Array(vec![
                    text(labels::LABEL),
                    text(labels::ZONE_USE),
                    text("audit.pseudonym"),
                    id(HOST_A),
                    text("plane/data/zone/x"),
                    Value::Int(1),
                ]),
            ),
        ];
        for (name, value) in refused {
            assert!(
                Info::decode(&cbor::encode(&value)).is_err(),
                "{name} was accepted"
            );
        }
        let mut trailing = zone_root_info(&ZONE, 1).unwrap();
        trailing.push(0x00);
        assert!(
            Info::decode(&trailing).is_err(),
            "trailing bytes were accepted"
        );
    }
}
