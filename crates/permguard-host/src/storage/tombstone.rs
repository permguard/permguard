// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Deletion: the tombstone is durable before anything is removed, and goes once the removal is.
//!
//! | Step                                  | Crash here leaves                    | Recovery ([`complete`])           |
//! | ------------------------------------- | ------------------------------------ | --------------------------------- |
//! | write `<name>.tomb`, flush it and dir | the tombstone and the file           | file unlinked, then the tombstone |
//! | unlink the file                       | the tombstone; the unlink maybe lost | the same                          |
//! | flush the directory                   | the tombstone                        | the tombstone is removed          |
//! | unlink the tombstone                  | maybe the tombstone                  | the same                          |
//! | flush the directory                   | nothing                              | nothing to do                     |
//!
//! A tombstone is a deletion in progress, not a record that the name may never be used again.
//! Content-addressed names are reused legitimately — an object a collection removed is pushed
//! again — so a tombstone that outlived its deletion would remove that new file at the next
//! recovery. It is removed only after the unlink is durable, and the file and the tombstone share a
//! directory, so any later flush of that directory, a publish's included, makes the removal durable
//! too. Recovery runs [`complete`] before the directory is written again.

use super::dir::{Dir, component};
use super::format;
use super::write::{read_view, replace_view};
use super::{Result, StorageError, crash::point};

/// The suffix of a tombstone's name.
pub const SUFFIX: &str = ".tomb";

fn tombstone_of(name: &str) -> Result<String> {
    Ok(format!("{}{SUFFIX}", component(name)?))
}

/// Deletes `name` below `dir`: tombstone first, then the unlink and the directory flush, then the
/// tombstone's removal and another flush.
pub fn delete(dir: &Dir, name: &str) -> Result<()> {
    if name.ends_with(SUFFIX) {
        return Err(StorageError::Name(name.to_owned()));
    }
    let tomb = tombstone_of(name)?;
    replace_view(dir, &tomb, format::TOMBSTONE, name.as_bytes())?;
    point("tombstone.written");
    dir.unlink(name)?;
    point("tombstone.unlinked");
    dir.sync()?;
    point("tombstone.parent_flushed");
    dir.unlink(&tomb)?;
    point("tombstone.removed");
    dir.sync()?;
    Ok(())
}

/// [`delete`], charged to `scope` — a maintenance scope for garbage collection and retention, which
/// may use the emergency floor: the tombstone is reserved before anything is written, and the
/// deleted file is freed once the deletion is durable.
pub fn delete_in(scope: &crate::storage::quota::Scope, dir: &Dir, name: &str) -> Result<()> {
    let deleted = std::fs::symlink_metadata(dir.child_path(name))
        .ok()
        .map(|metadata| metadata.len());
    let tomb = format::encode_file(format::TOMBSTONE, 0, name.as_bytes()).len() as u64;
    // The tombstone lives only for the deletion: reserved, never counted as used.
    let reservation = scope.reserve(tomb, 1)?;
    delete(dir, name)?;
    drop(reservation);
    if let Some(deleted) = deleted {
        scope.freed(deleted, 1)?;
    }

    Ok(())
}

/// Whether a deletion of `name` is in progress: its tombstone is durable and not yet removed.
pub fn is_pending(dir: &Dir, name: &str) -> Result<bool> {
    dir.exists(&tombstone_of(name)?)
}

/// Completes every deletion a crash interrupted; answers how many files it removed.
pub fn complete(dir: &Dir) -> Result<usize> {
    let mut removed = 0;
    let mut tombs = Vec::new();
    for tomb in dir
        .names()?
        .into_iter()
        .filter(|name| name.ends_with(SUFFIX))
    {
        let Some(body) = read_view(dir, &tomb, format::TOMBSTONE)? else {
            continue;
        };
        let name = String::from_utf8(body)
            .map_err(|_| StorageError::Corruption(format!("tombstone `{tomb}` names no file")))?;
        if format!("{name}{SUFFIX}") != tomb {
            return Err(StorageError::Corruption(format!(
                "tombstone `{tomb}` names `{name}`"
            )));
        }
        if dir.unlink(&name)? {
            removed += 1;
        }
        tombs.push(tomb);
    }
    if tombs.is_empty() {
        return Ok(removed);
    }
    dir.sync()?;
    for tomb in &tombs {
        dir.unlink(tomb)?;
    }
    dir.sync()?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::storage::write::{Published, publish_immutable};

    fn scratch(tag: &str) -> (std::path::PathBuf, Dir) {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-tombstone-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        let dir = Dir::create_root(&path).expect("a root");
        (path, dir)
    }

    #[test]
    fn a_deletion_removes_the_file_and_then_its_tombstone() {
        let (path, dir) = scratch("delete");
        std::fs::write(path.join("obj"), b"x").expect("a file");
        delete(&dir, "obj").expect("deleted");
        assert!(!dir.exists("obj").expect("asked"));
        assert!(
            !is_pending(&dir, "obj").expect("asked"),
            "the tombstone went"
        );
        assert!(dir.names().expect("listed").is_empty());
    }

    #[test]
    fn an_interrupted_deletion_completes_and_clears_its_tombstone() {
        let (path, dir) = scratch("interrupted");
        std::fs::write(path.join("obj"), b"x").expect("a file");
        replace_view(&dir, "obj.tomb", format::TOMBSTONE, b"obj").expect("a tombstone");
        assert!(is_pending(&dir, "obj").expect("asked"));
        assert_eq!(complete(&dir).expect("completed"), 1);
        assert!(!dir.exists("obj").expect("asked"));
        assert!(!is_pending(&dir, "obj").expect("asked"));
    }

    /// A name deleted and published again keeps its new file: no tombstone outlives its deletion.
    #[test]
    fn a_name_published_again_after_its_deletion_survives_recovery() {
        let (path, dir) = scratch("republished");
        std::fs::write(path.join("obj"), b"x").expect("a file");
        delete(&dir, "obj").expect("deleted");
        let same = |held: &[u8]| held == b"x";
        assert_eq!(
            publish_immutable(&dir, "obj", b"x", &same, &same).expect("published again"),
            Published::Written
        );
        assert_eq!(complete(&dir).expect("completed"), 0);
        assert!(dir.exists("obj").expect("asked"), "the new file is kept");
    }
}
