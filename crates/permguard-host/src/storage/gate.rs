// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The quota gate of the storage write primitives (BUG-0062, owner decision of 2026-11-20).
//!
//! The writers of every crate — the Host, the three Planes, decisions, events and streams — write
//! through this library's primitives: [`super::write::publish_immutable`],
//! [`super::write::replace_view`], [`super::write::replace_bytes`] and
//! [`super::journal::Journal::append`]. Each asks this gate for the scope of the directory it
//! writes in, and when a volume's quota is installed and holds that directory, reserves its bytes
//! and files there before anything is written: a write past `storage.quotas.host`, or below the
//! emergency floor, is refused `storage_quota_exceeded` or `storage_below_floor` and writes
//! nothing.
//!
//! | Path below the volume | Class                                                           |
//! | --------------------- | --------------------------------------------------------------- |
//! | `host/audit/`         | maintenance: the record of an action may use the floor down to   |
//! |                       | its reserve, so an operator's clean-up is still audited          |
//! | anything else         | ordinary                                                         |
//!
//! A store writing through `std::fs` is not charged; the quota's remeasure pass corrects that
//! drift once a minute. A process composes one volume, a test process may compose several: each
//! is installed under its root, and a directory is charged to the volume whose root holds it most
//! closely. Nothing is installed in a process that composes no Host: the primitives then charge
//! nothing, as they always did.

use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use super::quota::{Class, Quota, Scope};

/// The volumes whose quotas the primitives charge, by root.
static INSTALLED: RwLock<Vec<(PathBuf, Quota)>> = RwLock::new(Vec::new());

/// Charges every later write below `root` to `quota`: what the composition root calls once the
/// volume's quota is open. A root installed again is charged to its latest quota.
pub fn install(root: &Path, quota: Quota) {
    let mut installed = INSTALLED.write().unwrap_or_else(PoisonError::into_inner);
    installed.retain(|(held, _)| held != root);
    installed.push((root.to_path_buf(), quota));
}

/// Stops charging writes below `root`.
pub fn uninstall(root: &Path) {
    INSTALLED
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|(held, _)| held != root);
}

/// The scope a write in `dir` is charged to, when an installed volume holds it.
pub fn scope_for(dir: &Path) -> Option<Scope> {
    let installed = INSTALLED.read().unwrap_or_else(PoisonError::into_inner);
    let (root, quota) = installed
        .iter()
        .filter(|(root, _)| dir.starts_with(root))
        .max_by_key(|(root, _)| root.components().count())?;
    let class = if dir
        .strip_prefix(root)
        .is_ok_and(|below| below.starts_with(Path::new("host").join("audit")))
    {
        Class::Maintenance
    } else {
        Class::Ordinary
    };
    Some(quota.host(class))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::storage::Dir;
    use permguard_core::volume::{Floors, Limit};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-storage-gate-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    /// BUG-0062: a directory below an installed root is charged to its quota, the audit as
    /// maintenance; one outside every root is charged nothing; the closest root wins.
    #[test]
    fn a_write_is_charged_to_the_volume_that_holds_it() {
        let root = scratch("scope");
        let quota = Quota::open(
            Dir::open(&root).expect("opens"),
            Floors::default(),
            Limit::default(),
        )
        .expect("a quota");
        install(&root, quota);
        assert!(scope_for(&root.join("host").join("authz")).is_some());
        assert!(scope_for(&root.join("data")).is_some());
        assert!(scope_for(&std::env::temp_dir().join("elsewhere")).is_none());
        let audit = scope_for(&root.join("host").join("audit").join("trails")).expect("a scope");
        let ordinary = scope_for(&root.join("host").join("state")).expect("a scope");
        assert_ne!(format!("{audit:?}"), format!("{ordinary:?}"), "two classes");
        uninstall(&root);
        assert!(scope_for(&root.join("data")).is_none());
    }
}
