// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where the mirrors live on the volume, and what is there that should not be.
//!
//! ```text
//! <volume>/data/mirrors/<zone-id>/<ledger-id>/{FORMAT, objects/, refs/<ref>, LEDGER}
//! <volume>/data/mirrors/<authority-host>/<zone-id>/<ledger-id>/...      (WP-7.2a)
//! ```
//!
//! A ledger mirrored over a `policy.mirror` membership task lives under its authority, the
//! coordinator Host that serves it: its identity is `(authority_host_id, zone_id, ledger_id)`, and
//! two coordinators claiming one pair of ids land in two directories rather than one. An authority
//! is the 32 lowercase hex digits of a Host id, a zone a UUID with its dashes (the catalog mints
//! them so), so the two depths never read as each other; a server minting 32-hex zone ids would
//! be misread, and none of this product does. A ledger a release up to v0.1.6 mirrored from a
//! configured URL sits in the first shape: listed here so the round can remove it, and never
//! served (WP-7.7).
//!
//! The same shape the control plane keeps its own ledgers in, on purpose: an
//! operator who has seen one directory has seen both. Identities, not names,
//! name the directories — a zone renamed on the server must not orphan a
//! mirror, and two zones may not collide because somebody reused a name.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// One mirror this plane keeps: which ledger it is, and where it lives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mirror {
    /// The coordinator Host that serves it, as 32 lowercase hex digits: `None` for a mirror of a
    /// configured URL.
    pub authority: Option<String>,
    pub zone_id: String,
    pub ledger_id: String,
}

impl Mirror {
    /// Where this mirror lives under the mirrors root.
    pub fn path(&self, root: &Path) -> PathBuf {
        match &self.authority {
            Some(authority) => root.join(authority),
            None => root.to_path_buf(),
        }
        .join(&self.zone_id)
        .join(&self.ledger_id)
    }

    /// How it reads in a log line or an audit record.
    pub fn label(&self) -> String {
        match &self.authority {
            Some(authority) => format!("{authority}/{}/{}", self.zone_id, self.ledger_id),
            None => format!("{}/{}", self.zone_id, self.ledger_id),
        }
    }
}

/// Whether a directory name is an authority's: a Host id, 32 lowercase hex digits.
pub fn is_authority(name: &str) -> bool {
    name.len() == 32
        && name
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A Host id as the directory of its mirrors.
pub fn authority_name(host_id: &[u8; 16]) -> String {
    host_id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Every mirror currently on disk, whether or not it is still wanted.
///
/// Tolerant by design: a directory that does not look like a mirror is
/// ignored rather than reported, because the volume belongs to the operator
/// and this plane is a guest in it.
pub fn on_disk(root: &Path) -> Result<Vec<Mirror>> {
    let mut found = Vec::new();
    let zones = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(error) => return Err(error).context(format!("listing {}", root.display())),
    };

    for zone in zones {
        let zone = zone.with_context(|| format!("listing {}", root.display()))?;
        if !zone.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = zone.file_name().to_string_lossy().into_owned();
        if is_authority(&name) {
            let Ok(zones) = std::fs::read_dir(zone.path()) else {
                continue;
            };
            for held in zones.flatten() {
                if held.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                    ledgers_in(
                        &held.path(),
                        Some(&name),
                        &held.file_name().to_string_lossy(),
                        &mut found,
                    );
                }
            }
        } else {
            ledgers_in(&zone.path(), None, &name, &mut found);
        }
    }

    found.sort();
    Ok(found)
}

/// The mirrors of one zone directory.
fn ledgers_in(zone: &Path, authority: Option<&str>, zone_id: &str, found: &mut Vec<Mirror>) {
    let Ok(ledgers) = std::fs::read_dir(zone) else {
        return;
    };
    for ledger in ledgers.flatten() {
        if !ledger
            .file_type()
            .map(|kind| kind.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        found.push(Mirror {
            authority: authority.map(ToOwned::to_owned),
            zone_id: zone_id.to_owned(),
            ledger_id: ledger.file_name().to_string_lossy().into_owned(),
        });
    }
}

/// Removes a mirror the configuration no longer follows — or whose ledger the
/// server no longer has.
///
/// Three guards, because this deletes data: the path must be **inside** the
/// mirrors root, it must be a directory and not a link, and it must look like
/// a mirror (it carries the `LEDGER` identity this loop writes, the `FORMAT`
/// pin, or an `objects` directory). Anything
/// else is left exactly where it is and reported, because a plane that
/// deletes what it does not recognise is a plane nobody should run.
pub fn remove(root: &Path, mirror: &Mirror) -> Result<()> {
    let path = mirror.path(root);
    let root = root
        .canonicalize()
        .with_context(|| format!("resolving {}", root.display()))?;
    let resolved = path
        .canonicalize()
        .with_context(|| format!("resolving {}", path.display()))?;

    if !resolved.starts_with(&root) {
        anyhow::bail!(
            "{} resolves outside the mirrors root: refusing to remove it",
            path.display()
        );
    }
    let metadata = std::fs::symlink_metadata(&resolved)
        .with_context(|| format!("reading {}", resolved.display()))?;
    if !metadata.is_dir() {
        anyhow::bail!(
            "{} is not a directory: refusing to remove it",
            path.display()
        );
    }
    // Ours to remove if it looks like a mirror — the `LEDGER` file is the
    // strongest marker, because this loop is what writes it — or if it holds
    // no files at all, which is what a mirror of a ledger with no history yet
    // looked like before that file existed. Anything else is somebody's data
    // in our directory, and it stays.
    let looks_like_a_mirror = resolved.join(crate::authz::store::IDENTITY_FILE).exists()
        || resolved.join("FORMAT").exists()
        || resolved.join("objects").exists();
    if !looks_like_a_mirror && holds_files(&resolved) {
        anyhow::bail!(
            "{} does not look like a mirror: refusing to remove it",
            path.display()
        );
    }

    std::fs::remove_dir_all(&resolved)
        .with_context(|| format!("removing {}", resolved.display()))?;

    // A zone directory left empty is noise on the volume, and so is an authority's; removing them
    // is best-effort and never an error — another mirror may have just landed.
    if let Some(zone) = resolved.parent() {
        let _ = std::fs::remove_dir(zone);
        if mirror.authority.is_some()
            && let Some(authority) = zone.parent()
        {
            let _ = std::fs::remove_dir(authority);
        }
    }

    Ok(())
}

/// Whether a directory tree holds any regular file.
fn holds_files(path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.flatten().any(|entry| match entry.file_type() {
        Ok(kind) if kind.is_dir() => holds_files(&entry.path()),
        Ok(kind) => kind.is_file(),
        Err(_) => false,
    })
}

/// How many bytes one mirror occupies, for the gauge an operator watches to
/// see which zone is growing. Walks the directory rather than trusting a
/// cached number: the objects are immutable, but pulls add to them.
pub fn size_of(root: &Path, mirror: &Mirror) -> u64 {
    fn walk(path: &Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(path) else {
            return 0;
        };
        entries
            .flatten()
            .map(|entry| match entry.file_type() {
                Ok(kind) if kind.is_dir() => walk(&entry.path()),
                Ok(kind) if kind.is_file() => entry.metadata().map(|m| m.len()).unwrap_or(0),
                _ => 0,
            })
            .sum()
    }

    walk(&mirror.path(root))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-mirrors-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn plant(root: &Path, zone: &str, ledger: &str) -> Mirror {
        let mirror = Mirror {
            authority: None,
            zone_id: zone.to_owned(),
            ledger_id: ledger.to_owned(),
        };
        let path = mirror.path(root);
        std::fs::create_dir_all(path.join("objects/ab")).expect("the mirror is planted");
        std::fs::write(path.join("FORMAT"), b"1\n").expect("the pin is written");
        std::fs::write(path.join("objects/ab/cdef"), b"12345").expect("an object is written");
        mirror
    }

    #[test]
    fn an_absent_root_lists_nothing_rather_than_failing() {
        let root = scratch("absent").join("never-created");
        assert!(on_disk(&root).expect("an absent root is empty").is_empty());
    }

    #[test]
    fn what_is_on_disk_is_listed_by_identity() {
        let root = scratch("listing");
        plant(&root, "z-1", "l-1");
        plant(&root, "z-1", "l-2");
        plant(&root, "z-2", "l-3");
        std::fs::write(root.join("stray-file"), b"not a mirror").expect("writes");

        let found = on_disk(&root).expect("the listing works");
        assert_eq!(
            found.iter().map(Mirror::label).collect::<Vec<_>>(),
            vec!["z-1/l-1", "z-1/l-2", "z-2/l-3"]
        );
    }

    #[test]
    fn a_mirror_is_removed_and_its_empty_zone_with_it() {
        let root = scratch("remove");
        let mirror = plant(&root, "z-1", "l-1");

        remove(&root, &mirror).expect("the mirror is removed");
        assert!(!mirror.path(&root).exists());
        assert!(
            !root.join("z-1").exists(),
            "an empty zone directory is noise"
        );
    }

    #[test]
    fn a_zone_with_another_mirror_survives_a_removal() {
        let root = scratch("remove-one");
        let kept = plant(&root, "z-1", "keep");
        let dropped = plant(&root, "z-1", "drop");

        remove(&root, &dropped).expect("the mirror is removed");
        assert!(kept.path(&root).exists(), "the sibling is untouched");
    }

    #[test]
    fn what_does_not_look_like_a_mirror_is_never_removed() {
        let root = scratch("refuse");
        let stranger = Mirror {
            authority: None,
            zone_id: "z-1".to_owned(),
            ledger_id: "somebody-elses-data".to_owned(),
        };
        let path = stranger.path(&root);
        std::fs::create_dir_all(&path).expect("the directory exists");
        std::fs::write(path.join("important.txt"), b"not ours").expect("writes");

        let error = remove(&root, &stranger)
            .expect_err("an unrecognised directory is left alone")
            .to_string();
        assert!(error.contains("does not look like a mirror"), "{error}");
        assert!(path.join("important.txt").exists(), "and it is still there");
    }

    #[test]
    fn an_empty_mirror_is_ours_to_remove() {
        // What a mirror of a ledger with no history looks like: a directory,
        // and nothing in it.
        let root = scratch("empty");
        let mirror = Mirror {
            authority: None,
            zone_id: "z-1".to_owned(),
            ledger_id: "l-1".to_owned(),
        };
        std::fs::create_dir_all(mirror.path(&root)).expect("the directory exists");

        remove(&root, &mirror).expect("an empty mirror is removed");
        assert!(!mirror.path(&root).exists());
    }

    #[test]
    fn size_counts_what_the_mirror_actually_holds() {
        let root = scratch("size");
        let mirror = plant(&root, "z-1", "l-1");

        // The object (5 bytes) plus the FORMAT pin (2).
        assert_eq!(size_of(&root, &mirror), 7);
    }

    /// Two mirrors holding one object hold it each in their own store: content-addressed, never
    /// hard-linked, so removing one mirror leaves the other's object whole.
    #[test]
    fn mirrors_sharing_an_object_hold_it_apart() {
        use permguard_control_client::objects;
        use permguard_control_client::store::FsStore;

        let root = scratch("shared-object");
        let mirrors: Vec<Mirror> = ["one", "two"]
            .into_iter()
            .map(|ledger| Mirror {
                authority: Some("a".repeat(32)),
                zone_id: "zone".to_owned(),
                ledger_id: ledger.to_owned(),
            })
            .collect();
        let mut digests = Vec::new();
        for mirror in &mirrors {
            let path = mirror.path(&root);
            std::fs::create_dir_all(&path).expect("the mirror");
            std::fs::write(path.join(crate::authz::store::IDENTITY_FILE), b"{}").expect("marked");
            digests.push(
                objects::put(&FsStore::new(&path), "objects", b"one shared object")
                    .expect("stored"),
            );
        }
        assert_eq!(digests[0], digests[1], "one content, one address");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let mut held = Vec::new();
            for mirror in &mirrors {
                for entry in walk(&mirror.path(&root).join("objects")) {
                    held.push(std::fs::metadata(&entry).expect("the object").nlink());
                }
            }
            assert_eq!(held, vec![1, 1], "each its own file, none linked");
        }
        remove(&root, &mirrors[0]).expect("removed");
        assert_eq!(
            objects::get(
                &FsStore::new(mirrors[1].path(&root)),
                "objects",
                &digests[1]
            )
            .expect("reads"),
            Some(b"one shared object".to_vec()),
            "the other mirror's object is whole"
        );
    }

    /// The regular files below `path`.
    fn walk(path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(path).expect("lists").flatten() {
            if entry.path().is_dir() {
                files.extend(walk(&entry.path()));
            } else {
                files.push(entry.path());
            }
        }
        files
    }
}
