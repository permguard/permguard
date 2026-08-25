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

    /// How this mirror reads in a log line and a metric label.
    pub fn label(&self) -> String {
        format!("{}/{}", self.identity.zone_name, self.identity.ledger_name)
    }
}

/// Writes the identity file. Called by the synchronization loop on every
/// round, so a rename upstream reaches this plane with the next sync.
pub fn record(mirror_path: &Path, identity: &Identity) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(identity)
        .map_err(|error| format!("describing the ledger identity: {error}"))?;

    std::fs::write(mirror_path.join(IDENTITY_FILE), bytes)
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
    let Ok(zones) = std::fs::read_dir(root) else {
        return held;
    };
    for zone in zones.flatten() {
        if !zone.path().is_dir() {
            continue;
        }
        let Ok(ledgers) = std::fs::read_dir(zone.path()) else {
            continue;
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
    held.sort_by(|left, right| left.path.cmp(&right.path));

    held
}

/// The mirror a request names, if this plane holds it.
pub fn find(root: &Path, zone: &str, ledger: &str) -> Option<Mirror> {
    mirrors(root)
        .into_iter()
        .find(|mirror| mirror.answers_to(zone, ledger))
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
            zone_id: format!("{zone}-id"),
            zone_name: zone.to_owned(),
            ledger_id: format!("{ledger}-id"),
            ledger_name: ledger.to_owned(),
            server: "http://127.0.0.1:7556".to_owned(),
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
            mirrors(&root)[0].label(),
            "acme/main-ledger",
            "labels read as a person wrote them"
        );
    }
}
