// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which mirrors this plane holds, and which one a request names.
//!
//! # Directories are identities, requests are names
//!
//! A mirror lives at `<volume>/data/mirrors/<zone-id>/<ledger-id>` — identities, so
//! a rename on the control plane never moves a directory and two zones cannot
//! collide over a reused name. A PEP, on the other hand, names what a human
//! configured: `zone: "acme"`, `ledger: "main-ledger"`.
//!
//! The bridge is the `LEDGER` file the synchronization loop writes beside
//! every mirror: the identities *and* the names it was told, plus the server
//! that told it. Reading it costs one small file per mirror, so a lookup is a
//! directory listing and nothing more — and a request may name either form,
//! the identity or the name, because both are in front of us.
//!
//! # What is refused
//!
//! A zone/ledger pair with no directory is a **404**: this plane does not
//! serve that ledger, and saying so plainly is more useful than a deny that
//! looks like a policy decision. The same is true of a mirror that is present
//! but empty — a ledger nobody has applied to yet has no history to evaluate.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What the synchronization loop records beside a mirror, so a plane that
/// only sees the volume can still answer a request that names things.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub zone_id: String,
    pub zone_name: String,
    pub ledger_id: String,
    pub ledger_name: String,
    /// The server this mirror came from — what the audit record names.
    pub server: String,
    /// The coordinator Host that serves it, as 32 lowercase hex digits (WP-7.2a): absent for a
    /// mirror of a configured URL, and in an identity written before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// The `policy.mirror` task that listed it, `<membership-id>/<task-id>` (WP-7.2a): only that
    /// task's complete listing is evidence it is no longer served. Absent for a URL's mirror.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

/// The file that carries it, inside the mirror.
pub const IDENTITY_FILE: &str = "LEDGER";

/// One mirror on the volume: where it is, and what it is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub path: PathBuf,
    pub identity: Identity,
}

impl Mirror {
    /// Whether this mirror answers to the pair a request named — by name, or
    /// by identity, since a PEP configured with either is a PEP that works.
    pub fn answers_to(&self, zone: &str, ledger: &str) -> bool {
        (self.identity.zone_name == zone || self.identity.zone_id == zone)
            && (self.identity.ledger_name == ledger || self.identity.ledger_id == ledger)
    }

    /// How this mirror reads to a person: by its zone and ledger names. For answers to an authorized
    /// caller and the audit channel only — never a log line or a metric label.
    pub fn display_name(&self) -> String {
        format!("{}/{}", self.identity.zone_name, self.identity.ledger_name)
    }

    /// The mirror as a log names it: by its zone and ledger ids, never by their names, which are
    /// tenant identifiers P10 keeps out of logs. [`Self::display_name`] is for answers to an authorized
    /// caller.
    pub fn log_id(&self) -> String {
        format!("{}/{}", self.identity.zone_id, self.identity.ledger_id)
    }
}

/// Writes the identity file. Called by the synchronization loop on every
/// round, so a rename upstream reaches this plane with the next sync.
pub fn record(mirror_path: &Path, identity: &Identity) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(identity)
        .map_err(|error| format!("describing the ledger identity: {error}"))?;

    // Through the storage library (WP-1.11): atomic and flushed, so a crash never leaves a
    // torn identity for the next start to read.
    permguard_host::storage::Dir::open(mirror_path)
        .and_then(|dir| permguard_host::storage::write::replace_bytes(&dir, IDENTITY_FILE, &bytes))
        .map_err(|error| format!("writing the ledger identity: {error}"))
}

/// The freshness marker: its modification time is the moment this mirror was
/// last confirmed against its control plane.
///
/// Touched by the synchronization loop on every round that ends in a verified
/// answer — advanced, unchanged, or legitimately empty — because freshness is
/// about *confirmation*, not change: a ledger that never moves is perfectly
/// fresh as long as somebody keeps asking. Never touched on failure, which is
/// what lets its age mean something.
pub const SYNCED_FILE: &str = "SYNCED";

/// Marks this mirror as confirmed now.
pub fn touch_synced(mirror_path: &Path) {
    // Content-free on purpose: the mtime is the datum, and rewriting one byte
    // updates it atomically enough for a marker nothing parses.
    let _ = std::fs::write(mirror_path.join(SYNCED_FILE), b"");
}

/// How long ago this mirror was last confirmed, when it ever was.
///
/// `None` for a mirror no synchronization loop has confirmed — a volume fed by
/// other means — where "how stale" is a question this plane cannot answer.
pub fn synced_age(mirror_path: &Path) -> Option<std::time::Duration> {
    let modified = std::fs::metadata(mirror_path.join(SYNCED_FILE))
        .ok()?
        .modified()
        .ok()?;

    std::time::SystemTime::now().duration_since(modified).ok()
}

/// Reads the identity file of one mirror.
pub fn identity_of(mirror_path: &Path) -> Option<Identity> {
    let bytes = std::fs::read(mirror_path.join(IDENTITY_FILE)).ok()?;

    serde_json::from_slice(&bytes).ok()
}

/// Every mirror the volume holds, with its names.
///
/// A directory without a readable identity file is skipped rather than
/// guessed at: it is a mirror mid-creation, or one written by something that
/// is not this loop, and either way it is not something to serve from.
pub fn mirrors(root: &Path) -> Vec<Mirror> {
    let mut held = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return held;
    };
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        // An authority's directory holds zones (WP-7.2a); any other is a zone of a configured
        // URL's mirrors.
        if crate::mirrors::layout::is_authority(&entry.file_name().to_string_lossy()) {
            let Ok(zones) = std::fs::read_dir(entry.path()) else {
                continue;
            };
            for zone in zones.flatten() {
                identified_in(&zone.path(), &mut held);
            }
        } else {
            identified_in(&entry.path(), &mut held);
        }
    }
    held.sort_by(|left, right| left.path.cmp(&right.path));

    held
}

/// The mirrors of one zone directory that carry their identity.
fn identified_in(zone: &Path, held: &mut Vec<Mirror>) {
    if !zone.is_dir() {
        return;
    }
    let Ok(ledgers) = std::fs::read_dir(zone) else {
        return;
    };
    for ledger in ledgers.flatten() {
        let path = ledger.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(identity) = identity_of(&path) {
            held.push(Mirror { path, identity });
        }
    }
}

/// An alias the configuration assigns (WP-7.2d, F-17): the pair of names a request uses, and the
/// one authority whose mirror they resolve to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub zone: String,
    pub ledger: String,
    /// The coordinator Host, as the 32 lowercase hex digits its mirrors live under.
    pub authority: String,
}

impl Alias {
    /// The alias as the configuration declares it, its dashed authority as its directory names it.
    pub fn from_config(alias: &permguard_core::mirrors::MirrorAlias) -> Self {
        Self {
            zone: alias.zone.clone(),
            ledger: alias.ledger.clone(),
            authority: alias.authority.replace('-', ""),
        }
    }
}

type Assigned = std::sync::RwLock<std::collections::BTreeMap<PathBuf, Vec<Alias>>>;

/// The aliases each mirrors root resolves through, assigned once by the plane that serves it: the
/// gate, the decision path, the temporal path and the round all resolve names here, so none of
/// them can answer from another ledger than the one the others authorized.
fn assigned() -> &'static Assigned {
    static ASSIGNED: std::sync::OnceLock<Assigned> = std::sync::OnceLock::new();
    ASSIGNED.get_or_init(Default::default)
}

/// Assigns `aliases` to the mirrors under `root` (WP-7.2d).
pub fn assign_aliases(root: &Path, aliases: Vec<Alias>) {
    assigned()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(root.to_path_buf(), aliases);
}

/// The alias `root` assigns to the pair a request named, if any.
fn alias_of(root: &Path, zone: &str, ledger: &str) -> Option<Alias> {
    assigned()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(root)?
        .iter()
        .find(|alias| alias.zone == zone && alias.ledger == ledger)
        .cloned()
}

/// The mirrors that answer to `zone`/`ledger`: every mirror answering to the names, or, where an
/// alias assigns the pair, only the one under its authority — never another claimant.
fn answering(root: &Path, zone: &str, ledger: &str) -> Vec<Mirror> {
    let alias = alias_of(root, zone, ledger);
    mirrors(root)
        .into_iter()
        .filter(|mirror| mirror.answers_to(zone, ledger))
        .filter(|mirror| {
            alias.as_ref().is_none_or(|alias| {
                mirror.identity.authority.as_deref() == Some(alias.authority.as_str())
            })
        })
        .collect()
}

/// The mirrors that answer to `zone`/`ledger` when more than one does (WP-7.2a): empty when one
/// or none does. What a refusal names, so a contested ledger is not mistaken for one this plane
/// never mirrored. An alias settles the pair it assigns (WP-7.2d).
pub fn contested(root: &Path, zone: &str, ledger: &str) -> Vec<String> {
    let answering = answering(root, zone, ledger);
    if answering.len() > 1 {
        answering
            .into_iter()
            .map(|mirror| mirror.path.display().to_string())
            .collect()
    } else {
        Vec::new()
    }
}

/// Every pair of names more than one mirror answers to (WP-7.2a): `(zone, ledger)` by name, with
/// the mirrors that claim it. What a round reports, so a contest is seen before a request is
/// refused over it.
pub fn contests(root: &Path) -> Vec<((String, String), Vec<String>)> {
    let mut by_name: std::collections::BTreeMap<(String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    for mirror in mirrors(root) {
        let names = (
            mirror.identity.zone_name.clone(),
            mirror.identity.ledger_name.clone(),
        );
        // A pair an alias assigns is claimed only under its authority (WP-7.2d).
        if let Some(alias) = alias_of(root, &names.0, &names.1)
            && mirror.identity.authority.as_deref() != Some(alias.authority.as_str())
        {
            continue;
        }
        by_name.entry(names).or_default().push(mirror.log_id());
    }
    by_name
        .into_iter()
        .filter(|(_, claimants)| claimants.len() > 1)
        .collect()
}

/// The mirror a request names, if this plane holds it.
pub fn find(root: &Path, zone: &str, ledger: &str) -> Option<Mirror> {
    // Exactly one, or none: two mirrors answering to the same names — two authorities, or a
    // configured URL and a membership, claiming one ledger — are never told apart by the order a
    // directory lists them in (WP-7.2a). Neither is served until one of them goes, or an alias
    // says which authority the names mean (WP-7.2d).
    let mut answering = answering(root, zone, ledger).into_iter();
    let first = answering.next()?;
    answering.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-authz-store-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn identity(zone: &str, ledger: &str) -> Identity {
        Identity {
            task: None,
            authority: None,
            zone_id: format!("{zone}-id"),
            zone_name: zone.to_owned(),
            ledger_id: format!("{ledger}-id"),
            ledger_name: ledger.to_owned(),
            server: "http://127.0.0.1:6443".to_owned(),
        }
    }

    fn provision(root: &Path, zone: &str, ledger: &str) -> PathBuf {
        let path = root.join(format!("{zone}-id")).join(format!("{ledger}-id"));
        std::fs::create_dir_all(&path).expect("the mirror directory is created");
        record(&path, &identity(zone, ledger)).expect("the identity is recorded");

        path
    }

    #[test]
    fn a_request_may_name_the_ledger_or_its_identity() {
        let root = scratch("names");
        provision(&root, "acme", "main-ledger");

        assert!(find(&root, "acme", "main-ledger").is_some(), "by name");
        assert!(find(&root, "acme-id", "main-ledger-id").is_some(), "by id");
        assert!(
            find(&root, "acme", "main-ledger-id").is_some(),
            "and either way round"
        );
        assert!(find(&root, "acme", "other").is_none());
        assert!(find(&root, "other", "main-ledger").is_none());
    }

    #[test]
    fn a_directory_with_no_identity_is_not_something_to_serve_from() {
        let root = scratch("half");
        std::fs::create_dir_all(root.join("zone-id").join("ledger-id"))
            .expect("the directory is created");

        assert!(mirrors(&root).is_empty(), "mid-creation is not ready");
    }

    #[test]
    fn the_identity_written_is_the_identity_read() {
        let root = scratch("round-trip");
        let path = provision(&root, "acme", "main-ledger");

        assert_eq!(
            identity_of(&path).expect("the identity reads back"),
            identity("acme", "main-ledger")
        );
        assert_eq!(
            mirrors(&root)[0].display_name(),
            "acme/main-ledger",
            "labels read as a person wrote them"
        );
    }

    /// WP-7.2d: an alias as the file declares it names its authority as its mirrors live under.
    #[test]
    fn an_alias_from_the_file_names_the_authority_as_its_directory() {
        let alias = Alias::from_config(&permguard_core::mirrors::MirrorAlias {
            zone: "acme".to_owned(),
            ledger: "main".to_owned(),
            authority: "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
        });
        assert_eq!(alias.authority, "0193a1b2c3d47e5f8a9b0c1d2e3f4a5b");
        assert!(crate::mirrors::layout::is_authority(&alias.authority));
        assert_eq!(
            (alias.zone.as_str(), alias.ledger.as_str()),
            ("acme", "main")
        );
    }
}
