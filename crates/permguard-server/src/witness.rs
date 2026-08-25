// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Catching the one rotation mistake that quietly ruins an audit trail.
//!
//! Pseudonyms are keyed and versioned, and rotating means changing **both**: a new key, and a new
//! version for the tokens it produces. The version is what lets a later question — *is this record
//! about the same person as that one* — know which key to recompute with.
//!
//! Change the key and forget the version, and nothing fails. The server starts, records keep being
//! written, and every one of them claims to be `v1`. Months later, `v1` means two different keys:
//! the same person now has two tokens that cannot be recognised as the same person, two different
//! people have tokens that cannot be told apart by version, and there is no way to work out from the
//! records which is which. The damage is silent, cumulative, and unrepairable.
//!
//! So the server remembers, per version, what that version's key produces for one fixed input. If a
//! version ever produces something different, the key behind it changed without the version
//! changing, and the server refuses to start rather than write the first ambiguous record.
//!
//! # Why the witness discloses nothing
//!
//! It is the pseudonymiser's own output for a constant that is written in this file. Producing it
//! needs the key; having it does not reveal the key, any more than any other pseudonym in the trail
//! does. It is exactly as sensitive as the records it protects, and it is kept beside them.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use permguard_core::{Config, Pseudonymizer, Realm};

/// The input every key is asked to pseudonymise, so that two keys can be told apart.
///
/// A constant, and deliberately one that is not a plausible subject: it names the purpose, so a
/// human reading the file can see that it is not somebody's identifier.
const WITNESS_INPUT: &str = "permguard:audit-pseudonym-key-witness";

/// Where the witnesses are kept inside the volume.
const WITNESS_FILE: &str = "operations/state/audit-pseudonym-versions";

/// Returns where this deployment keeps its witnesses.
pub fn witness_path(config: &Config) -> PathBuf {
    config.resolve(WITNESS_FILE)
}

/// Refuses to start when the *server's* pseudonymisation key version now means a different key.
///
/// Does nothing when pseudonymisation is off, and records the version the first time it sees it.
pub fn check(config: &Config, pseudonymizer: Option<&dyn Pseudonymizer>) -> Result<()> {
    check_at(&witness_path(config), pseudonymizer)
}

/// The same guard for one realm, against the realm's own witness under `realms/<name>/state`.
///
/// A realm's key is its own, so its witness is its own too: a version that means one key in realm A
/// and another in realm B is not a mismatch, and must not read as one. A realm whose key changed
/// without its version changing refuses the start with the realm named — a mis-rotation that would
/// silently corrupt a realm's trail is a configuration error to fix, not a fault to serve through.
pub fn check_realm(config: &Config, realm: &Realm) -> Result<()> {
    let path = config.resolve(format!(
        "realms/{}/operations/state/audit-pseudonym-versions",
        realm.name()
    ));

    check_at(&path, realm.pseudonymizer().map(|policy| policy.as_ref())).with_context(|| {
        format!(
            "checking the pseudonymisation key of the realm `{}`",
            realm.name()
        )
    })
}

/// Refuses to start when a key version at `path` now means a different key than it did.
fn check_at(path: &Path, pseudonymizer: Option<&dyn Pseudonymizer>) -> Result<()> {
    let Some(pseudonymizer) = pseudonymizer else {
        return Ok(());
    };

    let version = pseudonymizer.key_version().to_owned();
    let witness = pseudonymizer.pseudonymize(WITNESS_INPUT);

    let recorded = read(path)?;

    if let Some((_, previous)) = recorded.iter().find(|(known, _)| *known == version) {
        if *previous == witness {
            return Ok(());
        }

        bail!(
            "the audit pseudonymisation key changed but its version did not: version `{version}` \
             has already produced records under a different key, and writing more under the same \
             version would make the two indistinguishable. Give the new key a new \
             `audit.pseudonym.key_version`, or restore the previous key. If this has genuinely \
             never written a record under `{version}`, remove {} and start again.",
            path.display()
        );
    }

    append(path, &version, &witness)
}

/// Reads the versions this deployment has already recorded under.
fn read(path: &Path) -> Result<Vec<(String, String)>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };

    Ok(text
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(version, witness)| (version.to_owned(), witness.to_owned()))
        .collect())
}

/// Records that this version has been seen, so the next start can compare against it.
fn append(path: &Path, version: &str, witness: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        restrict(parent, 0o700)?;
    }

    let mut text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };

    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }

    text.push_str(&format!("{version}\t{witness}\n"));

    fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    restrict(path, 0o600)
}

/// Narrows permissions where the platform has them.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("restricting {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
