// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Secrets, their witnesses and the keys derived from them (WP-3.3).
//!
//! ```text
//! host/state/witness/<reference>/<version>                              a root's witness
//! host/state/witness/zone-use/<authority>/<zone>/<purpose>/<scope>/<v>  a delivered key's witness
//! host/zone-use/<authority>/<zone>/<purpose>/<scope>/<version>          a delivered key (0600)
//! ```
//!
//! | Root                 | Derivation                                                                  | Who holds it            |
//! | -------------------- | --------------------------------------------------------------------------- | ----------------------- |
//! | a Host-local root    | `derive_host_local(root, owner, purpose, authority, resource, N)`           | the Host                |
//! | the coordinator root | `zone_root(zone, N)`, then `distributed_key(purpose, zone, scope, N)`       | the coordinator only    |
//! | a delivered key      | none: it is the distributed key of one `(purpose, zone, scope, N)`          | the members it was given |
//!
//! Configuration names a root by its `SecretRef`; the root is resolved through the existing
//! stores, refused under 256 bits, and witnessed per `(reference, version)`: other material under
//! a version already seen refuses the start. A root is never used directly: every key leaves this
//! module derived for one registered purpose, and a Plane gets a non-displayable handle that MACs,
//! never the bytes. Versions are integers written `vN` (owner decision of 2026-10-08).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};

use hmac::{Hmac, KeyInit, Mac as _};
use sha2::Sha256;
use zeroize::Zeroizing;

use permguard_core::domains::{digest, kdf as purposes};
use permguard_core::{SecretRef, SecretStore};
use permguard_objects::cbor::{self, Value};
use permguard_objects::crypto::kdf::{self, KEY_LEN, MIN_ROOT_LEN};

use crate::identity::record::uuid_text;
use crate::storage::volume::Volume;
use crate::storage::{Dir, StorageError, write};

/// The witnesses' directory below `host/state/`.
pub const WITNESS: &str = "witness";
/// The witnesses of a root by its role, whatever reference names it, below `host/state/witness/`.
pub const BY_ROLE: &str = "by-role";

/// The delivered zone keys' directory below `host/`.
pub const ZONE_USE: &str = purposes::ZONE_USE;

/// Why a secret did not resolve, verify or derive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsError {
    /// The store could not resolve the reference.
    Unresolved { reference: String, detail: String },
    /// The material is shorter than 256 bits.
    TooShort { reference: String, length: usize },
    /// Other material than the one witnessed under this version.
    Changed { what: String },
    /// A version that is not `v` and an integer of at least 1.
    Version(String),
    /// The witness or the key store could not be read or written.
    Storage(String),
    /// The derivation refused.
    Kdf(String),
    /// A scope its purpose does not take: the zone's shared pseudonyms are scoped by the zone.
    Scope,
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved { reference, detail } => {
                write!(f, "the secret `{reference}` did not resolve: {detail}")
            }
            Self::TooShort { reference, length } => write!(
                f,
                "the secret `{reference}` is {length} bytes, and a root is at least {MIN_ROOT_LEN}"
            ),
            Self::Changed { what } => write!(
                f,
                "{what} is other material than the one this version was first seen with: a new \
                 key takes a new version"
            ),
            Self::Version(text) => write!(
                f,
                "`{text}` is not a key version: `v` and an integer of at least 1, as `v1`"
            ),
            Self::Storage(detail) => write!(f, "the secrets' state: {detail}"),
            Self::Kdf(detail) => write!(f, "the derivation refused: {detail}"),
            Self::Scope => {
                f.write_str("the zone's shared pseudonyms are scoped by the zone itself")
            }
        }
    }
}

impl std::error::Error for SecretsError {}

impl From<StorageError> for SecretsError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<kdf::KdfError> for SecretsError {
    fn from(error: kdf::KdfError) -> Self {
        Self::Kdf(error.to_string())
    }
}

/// A key version: an integer of at least 1, written `vN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyVersion(u64);

impl KeyVersion {
    /// The version `n`, when it is at least 1.
    pub fn new(n: u64) -> Option<Self> {
        (n >= 1).then_some(Self(n))
    }

    /// The integer the KDF tuples carry.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl FromStr for KeyVersion {
    type Err = SecretsError;

    fn from_str(text: &str) -> Result<Self, SecretsError> {
        let refused = || SecretsError::Version(text.to_owned());
        let digits = text.strip_prefix('v').ok_or_else(refused)?;
        if digits.is_empty()
            || digits.starts_with('0')
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(refused());
        }
        let n: u64 = digits.parse().map_err(|_| refused())?;
        // The KDF encodes versions in the signed 64-bit range.
        if i64::try_from(n).is_err() {
            return Err(refused());
        }
        Self::new(n).ok_or_else(refused)
    }
}

impl fmt::Display for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// What a Host-local root is derived for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostPurpose {
    /// Pseudonyms of Host-scoped trails, realms and sinks.
    AuditPseudonym,
    /// Read-offset MACs, per API.
    StreamCursor,
}

impl HostPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuditPseudonym => purposes::AUDIT_PSEUDONYM,
            Self::StreamCursor => purposes::STREAM_CURSOR,
        }
    }
}

/// What a zone key is distributed for, and the scope it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZonePurpose {
    /// A zone's shared user pseudonyms: the scope is the zone itself.
    AuditPseudonym,
    /// Decision input tags: the scope is the ledger.
    DecisionCommitment,
}

impl ZonePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuditPseudonym => purposes::AUDIT_PSEUDONYM,
            Self::DecisionCommitment => purposes::DECISION_COMMITMENT,
        }
    }

    /// Whether `scope` is one this purpose takes in `zone`: the zone itself for pseudonyms, a
    /// ledger (any scope but the zone's own id) for input tags.
    pub fn takes(self, zone: &[u8; 16], scope: &[u8; 16]) -> bool {
        match self {
            Self::AuditPseudonym => scope == zone,
            Self::DecisionCommitment => true,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::AuditPseudonym, Self::DecisionCommitment]
            .into_iter()
            .find(|purpose| purpose.as_str() == text)
    }
}

/// A resolved root: at least 256 bits, zeroized on drop, never displayed.
#[derive(Clone)]
pub struct Root {
    material: Zeroizing<Vec<u8>>,
    version: KeyVersion,
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Root")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Root {
    pub fn version(&self) -> KeyVersion {
        self.version
    }

    /// A root from material already in hand: for the cursor key a store generates itself, and
    /// for tests. Refused under 256 bits.
    pub fn from_material(material: &[u8], version: KeyVersion) -> Result<Self, SecretsError> {
        if material.len() < MIN_ROOT_LEN {
            return Err(SecretsError::TooShort {
                reference: "a local root".to_owned(),
                length: material.len(),
            });
        }
        Ok(Self {
            material: Zeroizing::new(material.to_vec()),
            version,
        })
    }
}

/// The witness of `material`: HMAC-SHA256 under it over a fixed domain-separated constant. It
/// detects a substitution; it does not prove a secret store honest.
pub fn witness_of(material: &[u8]) -> [u8; 32] {
    // HMAC accepts a key of any length.
    let mut mac = match <Hmac<Sha256> as KeyInit>::new_from_slice(material) {
        Ok(mac) => mac,
        Err(_) => return [0; 32],
    };
    mac.update(digest::SECRET_WITNESS.as_bytes());
    mac.finalize().into_bytes().into()
}

/// A path component for a reference name: the name itself when it is plain, its SHA-256 hex
/// otherwise, so no name reaches outside the witness directory.
fn component(name: &str) -> String {
    // The names the witness directory uses itself, and the hashed form, are never a reference's.
    let reserved = [ZONE_USE, BY_ROLE].contains(&name) || name.starts_with("sha256-");
    let plain = !reserved
        && !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if plain {
        name.to_owned()
    } else {
        format!(
            "sha256-{}",
            permguard_objects::digest::Digest::compute(name.as_bytes())
                .to_string()
                .trim_start_matches("sha256:")
        )
    }
}

/// The witnesses of one volume.
#[derive(Debug)]
pub struct Witnesses {
    dir: Dir,
}

impl Witnesses {
    /// `host/state/witness/` of `volume`, created `0700`.
    pub fn open(volume: &Volume) -> Result<Self, SecretsError> {
        let dir = volume.host().subdir("state", true)?.subdir(WITNESS, true)?;
        dir.sweep_temps()?;
        Ok(Self { dir })
    }

    /// Checks `material` against the witness at `path`, writing it the first time: other material
    /// under a path already witnessed is refused as `what`.
    fn check(&self, path: &[String], material: &[u8], what: &str) -> Result<(), SecretsError> {
        let (name, parents) = path
            .split_last()
            .ok_or_else(|| SecretsError::Storage("an empty witness path".to_owned()))?;
        let mut dir: Option<Dir> = None;
        for parent in parents {
            dir = Some(dir.as_ref().unwrap_or(&self.dir).subdir(parent, true)?);
        }
        let dir = dir.as_ref().unwrap_or(&self.dir);
        let witness = witness_of(material);
        if let Some(held) = dir.read(name)? {
            return if equal(&held, &witness) {
                Ok(())
            } else {
                Err(SecretsError::Changed {
                    what: what.to_owned(),
                })
            };
        }
        write::publish_immutable(dir, name, &witness, &|_| true, &|held| held == witness)?;
        Ok(())
    }
}

/// Resolves `reference` at `version` from `store` for `role` (`audit-pseudonym`, `coordinator`):
/// at least 256 bits, and the material this version was first seen with, under this reference and
/// under this role, so pointing the role at another reference keeps the version honest too.
pub fn resolve(
    store: &dyn SecretStore,
    witnesses: &Witnesses,
    reference: &SecretRef,
    version: KeyVersion,
    role: &str,
) -> Result<Root, SecretsError> {
    let secret = store
        .resolve(reference)
        .map_err(|error| SecretsError::Unresolved {
            reference: reference.name().to_owned(),
            detail: error.to_string(),
        })?;
    if secret.len() < MIN_ROOT_LEN {
        return Err(SecretsError::TooShort {
            reference: reference.name().to_owned(),
            length: secret.len(),
        });
    }
    witnesses.check(
        &[component(reference.name()), version.to_string()],
        secret.expose(),
        &format!("the secret `{}` at {version}", reference.name()),
    )?;
    witnesses.check(
        &[BY_ROLE.to_owned(), component(role), version.to_string()],
        secret.expose(),
        &format!("the {role} root at {version}"),
    )?;
    Ok(Root {
        material: Zeroizing::new(secret.expose().to_vec()),
        version,
    })
}

/// A Host-local root bound to its owner: keys per purpose and resource, never a key of another
/// Host. The authority of a Host-local key is the owner itself.
pub struct HostLocal {
    root: Root,
    owner: [u8; 16],
}

impl fmt::Debug for HostLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostLocal")
            .field("owner", &uuid_text(&self.owner))
            .field("version", &self.root.version)
            .finish_non_exhaustive()
    }
}

impl HostLocal {
    pub fn new(root: Root, owner: [u8; 16]) -> Self {
        Self { root, owner }
    }

    pub fn version(&self) -> KeyVersion {
        self.root.version
    }

    /// The privacy policy of `resource`: pseudonyms of principals under this root, for the
    /// records a sink renders (`host`) or a realm's (`realm/<name>`).
    pub fn pseudonymizer(&self, resource: &str) -> Result<HostPseudonymizer, SecretsError> {
        Ok(HostPseudonymizer {
            key: self.key(HostPurpose::AuditPseudonym, resource)?,
            version: self.root.version,
            version_text: self.root.version.to_string(),
        })
    }

    /// The key of `purpose` for `resource`.
    pub fn key(
        &self,
        purpose: HostPurpose,
        resource: &str,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
        Ok(kdf::derive_host_local(
            &self.root.material,
            &self.owner,
            purpose.as_str(),
            &self.owner,
            resource,
            self.root.version.get(),
        )?)
    }
}

/// A Host-local pseudonymiser of one resource: `principal` identifiers under its key.
pub struct HostPseudonymizer {
    key: Zeroizing<[u8; KEY_LEN]>,
    version: KeyVersion,
    version_text: String,
}

impl fmt::Debug for HostPseudonymizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostPseudonymizer({}, redacted)", self.version)
    }
}

impl permguard_core::Pseudonymizer for HostPseudonymizer {
    fn key_version(&self) -> &str {
        &self.version_text
    }

    fn pseudonymize(&self, value: &str) -> String {
        // The encoding of two texts cannot fail; were it to, the value is not written raw.
        host_pseudonym(&self.key, self.version, "principal", value)
            .unwrap_or_else(|| format!("{}:unavailable", self.version))
    }
}

/// One delivered key's coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZoneTuple {
    pub authority: [u8; 16],
    pub zone: [u8; 16],
    pub purpose: ZonePurpose,
    pub scope: [u8; 16],
    pub version: KeyVersion,
}

impl ZoneTuple {
    fn path(&self) -> Vec<String> {
        vec![
            uuid_text(&self.authority),
            uuid_text(&self.zone),
            self.purpose.as_str().to_owned(),
            uuid_text(&self.scope),
            self.version.to_string(),
        ]
    }
}

/// The coordinator root: zone roots and the distributed keys of them, in memory only.
#[derive(Clone)]
pub struct Coordinator {
    root: Root,
    authority: [u8; 16],
}

impl fmt::Debug for Coordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Coordinator")
            .field("authority", &uuid_text(&self.authority))
            .field("version", &self.root.version)
            .finish_non_exhaustive()
    }
}

impl Coordinator {
    /// The coordinator of `authority` (this Host's `host_id`) over `root`.
    pub fn new(root: Root, authority: [u8; 16]) -> Self {
        Self { root, authority }
    }

    pub fn authority(&self) -> [u8; 16] {
        self.authority
    }

    pub fn version(&self) -> KeyVersion {
        self.root.version
    }

    /// The distributed key of `purpose` for `scope` in `zone`, at the root's version. The zone
    /// root is derived, used and dropped here: it never leaves this function.
    pub fn distributed(
        &self,
        purpose: ZonePurpose,
        zone: &[u8; 16],
        scope: &[u8; 16],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
        if !purpose.takes(zone, scope) {
            return Err(SecretsError::Scope);
        }
        let version = self.root.version.get();
        let zone_root = kdf::derive_zone_root(&self.root.material, &self.authority, zone, version)?;
        Ok(kdf::derive_distributed_key(
            &zone_root[..],
            &self.authority,
            purpose.as_str(),
            zone,
            scope,
            version,
        )?)
    }

    /// Delivers the key of `purpose` for `scope` in `zone` to a member's store: the local half of
    /// the `zone.secrets` task (WP-11 carries it between Hosts).
    pub fn deliver(
        &self,
        member: &ZoneKeys,
        purpose: ZonePurpose,
        zone: &[u8; 16],
        scope: &[u8; 16],
    ) -> Result<ZoneTuple, SecretsError> {
        let tuple = ZoneTuple {
            authority: self.authority,
            zone: *zone,
            purpose,
            scope: *scope,
            version: self.root.version,
        };
        member.store(&tuple, &*self.distributed(purpose, zone, scope)?)?;
        Ok(tuple)
    }
}

/// The delivered zone keys of one volume, each with its witness.
#[derive(Debug)]
pub struct ZoneKeys {
    dir: Dir,
    witnesses: Witnesses,
}

impl ZoneKeys {
    /// `host/zone-use/` of `volume`, created `0700`.
    pub fn open(volume: &Volume) -> Result<Self, SecretsError> {
        let dir = volume.host().subdir(ZONE_USE, true)?;
        dir.sweep_temps()?;
        Ok(Self {
            dir,
            witnesses: Witnesses::open(volume)?,
        })
    }

    fn directory(&self, tuple: &ZoneTuple, create: bool) -> Result<Option<Dir>, SecretsError> {
        let path = tuple.path();
        let mut dir: Option<Dir> = None;
        for part in &path[..path.len() - 1] {
            let parent = dir.as_ref().unwrap_or(&self.dir);
            let next = if create {
                parent.subdir(part, true)?
            } else {
                match existing(parent, part)? {
                    Some(next) => next,
                    None => return Ok(None),
                }
            };
            dir = Some(next);
        }
        Ok(dir)
    }

    /// Stores the key of `tuple` once: the same key again is a no-op, another key under the same
    /// tuple is refused.
    pub fn store(&self, tuple: &ZoneTuple, key: &[u8; KEY_LEN]) -> Result<(), SecretsError> {
        if !tuple.purpose.takes(&tuple.zone, &tuple.scope) {
            return Err(SecretsError::Scope);
        }
        let what = format!("the delivered key {}", tuple.path().join("/"));
        let dir = self
            .directory(tuple, true)?
            .ok_or_else(|| SecretsError::Storage("the zone key directory".to_owned()))?;
        let name = tuple.version.to_string();
        // The key on disk first: a refused key never leaves its witness behind.
        if let Some(held) = dir.read(&name)?
            && !equal(&held, key)
        {
            return Err(SecretsError::Changed { what });
        }
        let mut witness_path = vec![ZONE_USE.to_owned()];
        witness_path.extend(tuple.path());
        self.witnesses.check(&witness_path, key, &what)?;
        if dir.read(&name)?.is_none() {
            write::publish_immutable(&dir, &name, key, &|_| true, &|held| held == key)?;
        }
        Ok(())
    }

    /// The key of `tuple`, checked against its witness; `None` when none was delivered.
    pub fn load(
        &self,
        tuple: &ZoneTuple,
    ) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, SecretsError> {
        let Some(dir) = self.directory(tuple, false)? else {
            return Ok(None);
        };
        let Some(held) = dir.read(&tuple.version.to_string())? else {
            return Ok(None);
        };
        let key: [u8; KEY_LEN] = held.as_slice().try_into().map_err(|_| {
            SecretsError::Storage(format!("{} is not a key", tuple.path().join("/")))
        })?;
        let key = Zeroizing::new(key);
        let mut witness_path = vec![ZONE_USE.to_owned()];
        witness_path.extend(tuple.path());
        self.witnesses.check(
            &witness_path,
            &key[..],
            &format!("the delivered key {}", tuple.path().join("/")),
        )?;
        Ok(Some(key))
    }

    /// Every tuple delivered for `authority`, `purpose` and `version`, read once at start so the
    /// decision path never does I/O.
    pub fn delivered(
        &self,
        authority: &[u8; 16],
        purpose: ZonePurpose,
        version: KeyVersion,
    ) -> Result<Vec<ZoneTuple>, SecretsError> {
        let mut found = Vec::new();
        let Some(authority_dir) = existing(&self.dir, &uuid_text(authority))? else {
            return Ok(found);
        };
        for zone in authority_dir.subdirs()? {
            let Some(zone_id) = parse_uuid(&zone) else {
                continue;
            };
            let zone_dir = authority_dir.subdir(&zone, false)?;
            if !zone_dir
                .subdirs()?
                .iter()
                .any(|name| ZonePurpose::parse(name) == Some(purpose))
            {
                continue;
            }
            let purpose_dir = zone_dir.subdir(purpose.as_str(), false)?;
            for scope in purpose_dir.subdirs()? {
                let Some(scope_id) = parse_uuid(&scope) else {
                    continue;
                };
                let tuple = ZoneTuple {
                    authority: *authority,
                    zone: zone_id,
                    purpose,
                    scope: scope_id,
                    version,
                };
                if purpose_dir
                    .subdir(&scope, false)?
                    .read(&version.to_string())?
                    .is_some()
                {
                    found.push(tuple);
                }
            }
        }
        Ok(found)
    }
}

/// The subdirectory `name` of `dir`, when it exists.
fn existing(dir: &Dir, name: &str) -> Result<Option<Dir>, SecretsError> {
    if dir.subdirs()?.iter().any(|held| held == name) {
        Ok(Some(dir.subdir(name, false)?))
    } else {
        Ok(None)
    }
}

/// A UUID's canonical text, read back.
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if text.len() != 36 || hex.len() != 32 || text != uuid_text(&decode_hex(&hex)?) {
        return None;
    }
    decode_hex(&hex)
}

fn decode_hex(hex: &str) -> Option<[u8; 16]> {
    let mut bytes = [0u8; 16];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

/// The keys of one purpose by `(zone, scope)`.
type Keys = BTreeMap<([u8; 16], [u8; 16]), Zeroizing<[u8; KEY_LEN]>>;

/// Where a zone handle's keys come from.
enum Source {
    /// This Host is the coordinator: keys derived in memory.
    Coordinator(Coordinator),
    /// Keys delivered to this Host, read at start.
    Delivered(Keys),
}

/// A non-displayable, purpose-bound capability over a zone's distributed keys: it MACs under the
/// key of `(zone, scope)` and never shows a key. A tuple this Host neither coordinates nor was
/// delivered answers no MAC, never one under another key.
pub struct ZoneHandle {
    purpose: ZonePurpose,
    version: KeyVersion,
    source: Source,
    cache: Mutex<Keys>,
}

impl fmt::Debug for ZoneHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZoneHandle({}, {}, redacted)",
            self.purpose.as_str(),
            self.version
        )
    }
}

impl ZoneHandle {
    /// The keys of `purpose` this Host derives as coordinator.
    pub fn coordinated(purpose: ZonePurpose, coordinator: Coordinator) -> Self {
        Self {
            purpose,
            version: coordinator.version(),
            source: Source::Coordinator(coordinator),
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    /// The keys of `purpose` delivered to this Host by `authority` at `version`, read now.
    pub fn delivered(
        purpose: ZonePurpose,
        authority: &[u8; 16],
        version: KeyVersion,
        keys: &ZoneKeys,
    ) -> Result<Self, SecretsError> {
        let mut held = BTreeMap::new();
        for tuple in keys.delivered(authority, purpose, version)? {
            if let Some(key) = keys.load(&tuple)? {
                held.insert((tuple.zone, tuple.scope), key);
            }
        }
        Ok(Self {
            purpose,
            version,
            source: Source::Delivered(held),
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn purpose(&self) -> ZonePurpose {
        self.purpose
    }

    pub fn version(&self) -> KeyVersion {
        self.version
    }

    /// HMAC-SHA256 under the key of `(zone, scope)`, over `parts` in order; `None` when this Host
    /// holds no key for it.
    pub fn mac(&self, zone: &[u8; 16], scope: &[u8; 16], parts: &[&[u8]]) -> Option<[u8; 32]> {
        if !self.purpose.takes(zone, scope) {
            return None;
        }
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let key = match cache.get(&(*zone, *scope)) {
            Some(key) => key,
            None => {
                let derived = match &self.source {
                    Source::Coordinator(coordinator) => {
                        coordinator.distributed(self.purpose, zone, scope).ok()?
                    }
                    Source::Delivered(held) => held.get(&(*zone, *scope))?.clone(),
                };
                cache.entry((*zone, *scope)).or_insert(derived)
            }
        };
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key[..]).ok()?;
        for part in parts {
            mac.update(part);
        }
        Some(mac.finalize().into_bytes().into())
    }

    /// The zone's shared pseudonym of `identifier` of `identifier_type`; `None` without the key.
    pub fn pseudonym(
        &self,
        zone: &[u8; 16],
        identifier_type: &str,
        identifier: &str,
    ) -> Option<String> {
        let message = pseudonym_message(identifier_type, identifier)?;
        let tag = self.mac(zone, zone, &[digest::AUDIT_PSEUDONYM.as_bytes(), &message])?;
        Some(format!("{}:{}", self.version, hex(&tag[..16])))
    }
}

/// The message a pseudonym MACs after its domain: det-CBOR `[identifier_type, identifier]`, the
/// identifier with surrounding white space removed (owner decision of 2026-10-08).
pub fn pseudonym_message(identifier_type: &str, identifier: &str) -> Option<Vec<u8>> {
    cbor::encode(&Value::Array(vec![
        Value::Text(identifier_type.to_owned()),
        Value::Text(identifier.trim().to_owned()),
    ]))
    .ok()
}

/// A Host-local pseudonym under `key` (a `HostPurpose::AuditPseudonym` key of one resource).
pub fn host_pseudonym(
    key: &[u8; KEY_LEN],
    version: KeyVersion,
    identifier_type: &str,
    identifier: &str,
) -> Option<String> {
    let message = pseudonym_message(identifier_type, identifier)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).ok()?;
    mac.update(digest::AUDIT_PSEUDONYM.as_bytes());
    mac.update(&message);
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    Some(format!("{version}:{}", hex(&tag[..16])))
}

/// Equality in time independent of where two byte strings differ.
fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (l, r)| difference | (l ^ r))
            == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;
