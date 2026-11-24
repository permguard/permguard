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

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use permguard_core::{Config, Pseudonymizer, Realm};
use permguard_host::identity::witness::files::FileVersionWitnesses;
use permguard_host::identity::witness::{self, HostScope, VersionWitnesses, Witnessed};

/// The input every key is asked to pseudonymise, so that two keys can be told apart.
///
/// A constant, and deliberately one that is not a plausible subject: it names the purpose, so a
/// human reading the file can see that it is not somebody's identifier.
const WITNESS_INPUT: &str = "permguard:audit-pseudonym-key-witness";

/// Returns where a deployment on the file backend keeps its server's witnesses.
pub fn witness_path(config: &Config) -> PathBuf {
    FileVersionWitnesses::path_below(config.working_dir(), None)
}

/// Refuses to start when the *server's* pseudonymisation key version now means a different key.
///
/// Does nothing when pseudonymisation is off, and records the version the first time it sees it.
pub fn check(
    witnesses: &dyn VersionWitnesses,
    pseudonymizer: Option<&dyn Pseudonymizer>,
) -> Result<()> {
    check_in(witnesses, None, pseudonymizer, None)
}

/// [`check`] for the Host `scope` names (BUG-0079): a key version is witnessed per Host, so the
/// new Host an identity reset provisions records its own derivation under the labels configured,
/// and the retired one's stay its own.
pub fn check_for(
    witnesses: &dyn VersionWitnesses,
    pseudonymizer: Option<&dyn Pseudonymizer>,
    scope: &HostScope,
) -> Result<()> {
    check_in(witnesses, None, pseudonymizer, Some(scope))
}

/// The same guard for one realm, against the realm's own witness.
///
/// A realm's key is its own, so its witness is its own too: a version that means one key in realm A
/// and another in realm B is not a mismatch, and must not read as one. A realm whose key changed
/// without its version changing refuses the start with the realm named — a mis-rotation that would
/// silently corrupt a realm's trail is a configuration error to fix, not a fault to serve through.
pub fn check_realm(
    witnesses: &dyn VersionWitnesses,
    realm: &Realm,
    scope: Option<&HostScope>,
) -> Result<()> {
    check_in(
        witnesses,
        Some(realm.name()),
        realm.pseudonymizer().map(|policy| policy.as_ref()),
        scope,
    )
    .with_context(|| {
        format!(
            "checking the pseudonymisation key of the realm `{}`",
            realm.name()
        )
    })
}

/// Refuses to start when a key version of `realm`, the server's own when `None`, now means a
/// different key than it did.
fn check_in(
    witnesses: &dyn VersionWitnesses,
    realm: Option<&str>,
    pseudonymizer: Option<&dyn Pseudonymizer>,
    scope: Option<&HostScope>,
) -> Result<()> {
    let Some(pseudonymizer) = pseudonymizer else {
        return Ok(());
    };

    let version = pseudonymizer.key_version().to_owned();
    let witness = pseudonymizer.pseudonymize(WITNESS_INPUT);

    // Checked and recorded in one step of the store: two starts never both record a version.
    let mut outcome = Witnessed::Holds;
    witnesses
        .update(realm, &mut |recorded| {
            let (checked, changed) =
                witness::check(recorded, &version, &witness, scope, |held, now| held == now);
            outcome = checked;
            changed
        })
        .context("reading the witnesses of the pseudonymisation key versions")?;
    if outcome == Witnessed::KeyChanged {
        bail!(
            "the audit pseudonymisation key changed but its version did not: version `{version}` \
             has already produced records under a different key, and writing more under the same \
             version would make the two indistinguishable. Give the new key a new \
             `audit.pseudonym.key_version`, or restore the previous key. After an upgrade to \
             per-Host, per-resource pseudonyms (WP-3.3) the key is the same and its derivation is \
             not: raise the version (`v2` after `v1`). If this has genuinely never written a \
             record under `{version}`, remove {} and start again.",
            witnesses.place(realm)
        );
    }
    Ok(())
}
