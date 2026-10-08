// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one-time migration of a ring the directory key manager kept before the rings (WP-3.1),
//! through the WP-1.9 framework (owner decisions of 2026-10-08).
//!
//! | Layout `keys-<ring>` | Where                          | What                                          |
//! | -------------------- | ------------------------------ | --------------------------------------------- |
//! | version 1            | the legacy directory, as it is | `ring.json` and a PKCS#8 PEM per private key   |
//! | version 2            | `host/keys/<ring>`             | the ring's journal, `public/`, `private/`      |
//!
//! | Legacy state | Journal                                                     | Private half      |
//! | ------------ | ----------------------------------------------------------- | ----------------- |
//! | `published`  | `prepublished`                                              | carried           |
//! | `active`     | `prepublished`, `activated`                                 | carried           |
//! | `retired`    | `prepublished`, `activated`, `retired`, `destroyed`         | left behind       |
//! | `archived`   | `prepublished`, `activated`, `retired`, `destroyed`         | already gone      |
//!
//! A retired or archived key stays in the published set as retired-public, and maintenance
//! archives it once `retain` has passed. Its `destroyed` entry speaks for `host/keys`: the PEM a
//! retired key left in the legacy directory goes with that directory at `migrate finalize`. Each key keeps its material and its thumbprint; its kid
//! becomes `<ring>:<thumbprint>`, and an artifact signed under the bare thumbprint keeps verifying
//! through the legacy alias ([`super::selects`]). The legacy directory is never written: it is the
//! old generation, kept until `migrate finalize`. A volume with no legacy ring declares version 2
//! at once.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;

use permguard_core::assurance::AssuranceProfile;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::crypto::thumbprint;

use super::record::{Entry, Kind};
use super::ring::{JOURNAL, PRIVATE, PUBLIC, check_history, jwk_of};
use super::{FileKeyProvider, PublicKey};
use crate::storage::migrate::{Built, Layout, Migration, Preflight};
use crate::storage::volume::Volume;
use crate::storage::write::{Published, publish_immutable};
use crate::storage::{Dir, Result, StorageError, sequence};

/// The layout version the legacy directory is declared at.
pub const SOURCE_VERSION: u16 = 1;
/// The layout version of `host/keys/<ring>`.
pub const TARGET_VERSION: u16 = 2;
/// The file the directory key manager described its ring in.
pub const LEGACY_RING: &str = "ring.json";

/// The layout subsystem of `ring`: `keys-<ring>`, its dots as hyphens.
pub fn subsystem(ring: &str) -> String {
    format!("keys-{}", ring.replace('.', "-"))
}

/// The layouts a Host's rings are laid out under, and the versions this build reads: version 1
/// only to migrate it.
pub fn layouts() -> Vec<(&'static str, crate::storage::migrate::Reads)> {
    use crate::storage::migrate::Reads;
    vec![
        (
            "keys-host-operations",
            Reads::from(SOURCE_VERSION, TARGET_VERSION),
        ),
        (
            "keys-control-attest",
            Reads::from(SOURCE_VERSION, TARGET_VERSION),
        ),
        (
            "keys-data-attest",
            Reads::from(SOURCE_VERSION, TARGET_VERSION),
        ),
    ]
}

/// Where `ring` lives once migrated, relative to the volume root.
pub fn target(ring: &str) -> String {
    format!(
        "{}/{}/{ring}",
        crate::storage::volume::HOST,
        super::ring::DIRECTORY
    )
}

#[derive(Debug, Deserialize)]
struct LegacyRing {
    #[serde(default)]
    keys: Vec<LegacyKey>,
}

#[derive(Debug, Deserialize)]
struct LegacyKey {
    kid: String,
    state: String,
    #[serde(default = "edwards")]
    algorithm: String,
    public_key: String,
    created_at: u64,
    #[serde(default)]
    activated_at: Option<u64>,
    #[serde(default)]
    retired_at: Option<u64>,
}

fn edwards() -> String {
    "EdDSA".to_owned()
}

fn refused(detail: impl Into<String>) -> StorageError {
    StorageError::Refused(detail.into())
}

/// The migration of one legacy ring to `host/keys/<ring>`.
#[derive(Debug, Clone)]
pub struct Legacy {
    ring: &'static str,
    subsystem: String,
    now: u64,
}

impl Legacy {
    pub fn new(ring: &'static str, now: u64) -> Self {
        Self {
            ring,
            subsystem: subsystem(ring),
            now,
        }
    }

    /// The journal entries the legacy ring amounts to, in an order the ring's history allows:
    /// the keys that stopped signing, oldest first, then the active key, then the keys waiting.
    fn entries<'a>(
        &self,
        legacy: &'a LegacyRing,
        suite: Suite,
    ) -> Result<Vec<(Entry, &'a LegacyKey)>> {
        let rank = |key: &LegacyKey| match key.state.as_str() {
            "retired" | "archived" => 0,
            "active" => 1,
            _ => 2,
        };
        let mut keys: Vec<&LegacyKey> = legacy.keys.iter().collect();
        keys.sort_by_key(|key| (rank(key), key.created_at));
        let mut entries = Vec::new();
        let mut seq = 0u64;
        let mut epoch = 0u64;
        let mut push = |kind: Kind, kid: &str, at: u64, jwk: Option<String>, epoch: u64| {
            seq += 1;
            Entry {
                seq,
                kind,
                kid: kid.to_owned(),
                epoch,
                at,
                operation_id: None,
                reason: None,
                jwk,
                compromised_at: None,
            }
        };
        for key in keys {
            let public = self.public_key(key, suite)?;
            let kid = thumbprint::kid(self.ring, &key.kid);
            let jwk = serde_json::to_string(&jwk_of(&kid, &public))
                .map_err(|error| refused(error.to_string()))?;
            epoch += 1;
            entries.push((
                push(Kind::Prepublished, &kid, key.created_at, Some(jwk), epoch),
                key,
            ));
            let activated = key.activated_at.unwrap_or(key.created_at);
            match key.state.as_str() {
                "published" => {}
                "active" => {
                    entries.push((push(Kind::Activated, &kid, activated, None, epoch), key));
                }
                "retired" | "archived" => {
                    entries.push((push(Kind::Activated, &kid, activated, None, epoch), key));
                    let retired = key.retired_at.unwrap_or(self.now);
                    entries.push((push(Kind::Retired, &kid, retired, None, epoch), key));
                    entries.push((push(Kind::Destroyed, &kid, self.now, None, epoch), key));
                }
                other => {
                    return Err(refused(format!(
                        "the legacy key `{}` is in the state `{other}`, which no ring had",
                        key.kid
                    )));
                }
            }
        }
        Ok(entries)
    }

    /// The public half of a legacy key, checked against its kid: the bare thumbprint of exactly
    /// that material.
    fn public_key(&self, key: &LegacyKey, suite: Suite) -> Result<PublicKey> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&key.public_key)
            .map_err(|error| refused(format!("the legacy key `{}`: {error}", key.kid)))?;
        let held = thumbprint::jwk_thumbprint(suite, &bytes)
            .map_err(|error| refused(format!("the legacy key `{}`: {error}", key.kid)))?;
        if held != key.kid {
            return Err(StorageError::Corruption(format!(
                "the legacy key `{}` is not the thumbprint of the key it describes",
                key.kid
            )));
        }
        Ok(PublicKey { suite, bytes })
    }
}

/// Reads a PKCS#8 PEM body back to DER.
fn from_pem(text: &str) -> Option<Vec<u8>> {
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect();
    STANDARD.decode(body).ok()
}

impl Migration for Legacy {
    fn subsystem(&self) -> &str {
        &self.subsystem
    }

    fn source_version(&self) -> u16 {
        SOURCE_VERSION
    }

    fn target_version(&self) -> u16 {
        TARGET_VERSION
    }

    fn build(&self, old: &Dir, new: &Dir) -> Result<Built> {
        let text = old
            .read(LEGACY_RING)?
            .ok_or_else(|| refused(format!("{} holds no {LEGACY_RING}", old.path().display())))?;
        let legacy: LegacyRing = serde_json::from_slice(&text)
            .map_err(|error| StorageError::Corruption(format!("{LEGACY_RING}: {error}")))?;
        let algorithms: std::collections::BTreeSet<&str> = legacy
            .keys
            .iter()
            .map(|key| key.algorithm.as_str())
            .collect();
        let suite = match algorithms.into_iter().collect::<Vec<_>>().as_slice() {
            ["EdDSA"] => Suite::Ed25519Sha256V1,
            ["ES256"] => Suite::P256Sha256V1,
            [] => return Err(refused(format!("{LEGACY_RING} holds no key"))),
            other => {
                return Err(refused(format!(
                    "{LEGACY_RING} holds keys of {other:?}: a ring holds one suite, and a legacy \
                     ring that changed algorithm is migrated once its old keys aged out"
                )));
            }
        };
        let entries = self.entries(&legacy, suite)?;
        let history: Vec<Entry> = entries.iter().map(|(entry, _)| entry.clone()).collect();
        check_history(self.ring, &history)
            .map_err(|detail| refused(format!("the legacy ring does not migrate: {detail}")))?;

        let public = new.subdir(PUBLIC, true)?;
        let provider = FileKeyProvider::new(new.subdir(PRIVATE, true)?);
        let mut files = 1;
        for (entry, key) in &entries {
            if entry.kind != Kind::Prepublished {
                continue;
            }
            let jwk = entry.jwk.as_deref().unwrap_or_default();
            let readable =
                |bytes: &[u8]| serde_json::from_slice::<serde_json::Value>(bytes).is_ok();
            let same = |bytes: &[u8]| bytes == jwk.as_bytes();
            match publish_immutable(
                &public,
                &format!("{}.jwk", key.kid),
                jwk.as_bytes(),
                &readable,
                &same,
            )? {
                Published::Written | Published::AlreadyThere => files += 1,
            }
            if matches!(key.state.as_str(), "published" | "active") {
                let pem = old.read(&format!("{}.pem", key.kid))?.ok_or_else(|| {
                    StorageError::Corruption(format!(
                        "the legacy ring names `{}` {} and its private half is not held",
                        key.kid, key.state
                    ))
                })?;
                let pkcs8 =
                    zeroize::Zeroizing::new(from_pem(&String::from_utf8_lossy(&pem)).ok_or_else(
                        || StorageError::Corruption(format!("{}.pem is not a PEM key", key.kid)),
                    )?);
                let (slot, held) = provider.import(suite, &pkcs8).map_err(|error| {
                    StorageError::Corruption(format!("{}.pem: {error}", key.kid))
                })?;
                if slot != key.kid || held.bytes != self.public_key(key, suite)?.bytes {
                    return Err(StorageError::Corruption(format!(
                        "{}.pem holds another key than the ring describes",
                        key.kid
                    )));
                }
                files += 1;
            }
        }
        for (entry, _) in &entries {
            let bytes = entry.encode().map_err(|error| refused(error.to_string()))?;
            sequence::append(new, JOURNAL, &bytes)?;
        }
        Ok(Built {
            carried: Vec::new(),
            // The ring file becomes the journal, each PEM a PKCS#8 slot: keys, never evidence.
            dropped: old.names()?,
            files,
        })
    }
}

/// What [`lay_out`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Laid {
    /// No legacy ring: version 2 declared where the ring is.
    Fresh,
    /// The legacy ring was migrated now.
    Migrated,
    /// Laid out already.
    Current,
}

/// The legacy directory of `ring` relative to the volume root, when it holds a ring to migrate;
/// a legacy ring outside the volume is refused (owner decision of 2026-10-08).
fn legacy_relative(volume: &Volume, legacy: Option<&Path>) -> Result<Option<String>> {
    let Some(legacy) = legacy else {
        return Ok(None);
    };
    // An unreadable directory is an error, never "no legacy ring": a ring declared fresh over
    // one would never be migrated.
    let held = legacy
        .join(LEGACY_RING)
        .try_exists()
        .map_err(|error| refused(format!("reading {}: {error}", legacy.display())))?;
    if !held {
        return Ok(None);
    }
    let root = volume.root();
    // Resolved, so a `..` or a link cannot carry a directory outside the volume past the check.
    let resolved = |path: &Path| {
        path.canonicalize()
            .map_err(|error| refused(format!("resolving {}: {error}", path.display())))
    };
    let legacy = resolved(legacy)?;
    let root = resolved(root)?;
    let relative = legacy
        .strip_prefix(&root)
        .ok()
        .and_then(Path::to_str)
        .filter(|relative| !relative.is_empty())
        .ok_or_else(|| {
            refused(format!(
                "the legacy key ring at {} is outside the volume {}: move it into the volume, \
                 then start again",
                legacy.display(),
                root.display()
            ))
        })?;
    Ok(Some(relative.replace(std::path::MAIN_SEPARATOR, "/")))
}

/// Whether `ring` has a legacy ring at `legacy` still to migrate.
pub fn needs_migration(volume: &Volume, ring: &'static str, legacy: Option<&Path>) -> Result<bool> {
    let layout = Layout::open(volume, &subsystem(ring))?;
    Ok(match layout.manifest()? {
        Some(manifest) => manifest.active.version == SOURCE_VERSION,
        None => legacy_relative(volume, legacy)?.is_some(),
    })
}

/// Lays `ring` out at version 2 before it opens: a legacy ring at `legacy` is migrated through the
/// framework, under `profile`'s preflight and with `backup` declared; otherwise version 2 is
/// declared at `host/keys/<ring>`.
pub fn lay_out(
    volume: &Volume,
    ring: &'static str,
    legacy: Option<&Path>,
    profile: AssuranceProfile,
    backup: Option<String>,
    now: u64,
) -> Result<Laid> {
    let layout = Layout::open(volume, &subsystem(ring))?;
    match layout.manifest()? {
        Some(manifest) if manifest.active.version == TARGET_VERSION => return Ok(Laid::Current),
        Some(_) => {}
        None => match legacy_relative(volume, legacy)? {
            None => {
                layout.declare(TARGET_VERSION, &target(ring), now)?;
                return Ok(Laid::Fresh);
            }
            Some(relative) => {
                layout.declare(SOURCE_VERSION, &relative, now)?;
            }
        },
    }
    layout.migrate(
        &Legacy::new(ring, now),
        Preflight::new(profile, &target(ring), backup, now),
    )?;
    Ok(Laid::Migrated)
}

#[cfg(test)]
mod tests;
