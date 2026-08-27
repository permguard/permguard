// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where the local half lives — the seam both layers of the engine speak.
//!
//! The CLI passes the filesystem implementation rooted at a workspace; a
//! browser would pass one over its own storage; a mirror on a volume would
//! pass one rooted there. Same logic, different shelves — which is why
//! neither layer ever names `std::fs` outside this file.

use std::fs;
use std::path::{Path, PathBuf};

/// One consumer's storage. Paths are relative, `/`-separated, and never
/// interpreted by the engine beyond joining segments it validated itself.
pub trait Store: Send + Sync {
    /// Reads a file, `None` when it does not exist.
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, String>;
    /// Writes a file, creating parents.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), String>;
    /// Whether a file exists.
    fn exists(&self, path: &str) -> bool;
    /// Lists the entries of a directory: `(name, is_directory)`. An absent
    /// directory lists empty.
    fn list(&self, path: &str) -> Result<Vec<(String, bool)>, String>;
    /// Creates a file only if it does not exist — atomically, the primitive
    /// the lock is built on. `false` means someone else holds it.
    fn create_exclusive(&self, path: &str, bytes: &[u8]) -> Result<bool, String>;
    /// Removes a file; removing an absent file succeeds.
    fn remove(&self, path: &str) -> Result<(), String>;
}

/// The filesystem implementation.
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    /// A store rooted at a directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory this store lives in.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// The path inside this store, or a refusal.
    ///
    /// Every path a store is given is **relative to its root and contained by it**. Pushing the
    /// segments unchecked let `..` walk out of the root, and a workspace is data — a policy
    /// repository somebody else wrote, read by `validate` and shipped by `apply`. A path that
    /// leaves the root is refused rather than resolved, because there is no legitimate caller
    /// that needs one: the one place a workspace path may say `..` is a case file naming its
    /// request, and that is resolved to a contained path before it ever reaches here.
    fn resolve(&self, path: &str) -> Result<PathBuf, String> {
        // A leading separator is refused rather than ignored. Treating `/etc/hosts` as
        // `etc/hosts` inside the root is safe — it is contained — but it answers a different
        // question than the one asked, and a store that quietly reinterprets a path is a store
        // whose refusals cannot be reasoned about.
        if path.starts_with('/') {
            return Err(format!(
                "refusing `{path}`: a store path is relative to its root"
            ));
        }

        let mut resolved = self.root.clone();

        for segment in path.split('/') {
            match segment {
                "" | "." => continue,
                ".." => {
                    return Err(format!(
                        "refusing `{path}`: a store path may not leave its root"
                    ));
                }
                segment if Path::new(segment).is_absolute() || segment.contains('\\') => {
                    return Err(format!(
                        "refusing `{path}`: `{segment}` is not a single relative name"
                    ));
                }
                segment => resolved.push(segment),
            }
        }

        Ok(resolved)
    }

    /// Refuses a path that reaches its target through a symbolic link — at any step.
    ///
    /// Checked with `symlink_metadata`, which does not follow, on **every component below the
    /// root**. Checking only the last one refused `partition/linked.cedar` and let
    /// `linked-directory/policy.cedar` through, which is the same escape one level up: a link
    /// inside a workspace pointed anywhere on the host, and its target was read as a policy and
    /// then pushed to the ledger.
    ///
    /// The walk is from the root outwards, so the message names the component that leaves, and a
    /// store below a legitimately symlinked root — a temp directory on macOS is one — still works:
    /// the root itself is never examined, only what a path adds to it.
    fn refuse_links(&self, path: &str) -> Result<(), String> {
        let mut walked = self.root.clone();

        for segment in path.split('/') {
            if segment.is_empty() || segment == "." {
                continue;
            }
            walked.push(segment);

            match fs::symlink_metadata(&walked) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!(
                        "refusing `{path}`: `{segment}` is a symbolic link, and a store holds its \
                         own files"
                    ));
                }
                // Absent is not a link, and is the caller's business: `read` answers `None`,
                // `write` creates it. What matters is that nothing on the way there redirects.
                _ => {}
            }
        }

        Ok(())
    }
}

impl Store for FsStore {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let resolved = self.resolve(path)?;
        self.refuse_links(path)?;

        match fs::read(&resolved) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("reading {path}: {error}")),
        }
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), String> {
        let resolved = self.resolve(path)?;
        self.refuse_links(path)?;
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("creating {path}: {error}"))?;
        }
        fs::write(&resolved, bytes).map_err(|error| format!("writing {path}: {error}"))
    }

    fn exists(&self, path: &str) -> bool {
        // A path this store would refuse does not exist as far as it is concerned.
        self.resolve(path)
            .is_ok_and(|resolved| self.refuse_links(path).is_ok() && resolved.exists())
    }

    fn list(&self, path: &str) -> Result<Vec<(String, bool)>, String> {
        let resolved = self.resolve(path)?;
        self.refuse_links(path)?;
        let entries = match fs::read_dir(&resolved) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("listing {path}: {error}")),
        };
        let mut listed = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("listing {path}: {error}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // `file_type` does not follow, so a symlinked directory is not reported as one and
            // the walk does not descend through it.
            let kind = entry
                .file_type()
                .map_err(|error| format!("listing {path}: {error}"))?;
            if kind.is_symlink() {
                continue;
            }
            listed.push((name, kind.is_dir()));
        }
        listed.sort();
        Ok(listed)
    }

    fn create_exclusive(&self, path: &str, bytes: &[u8]) -> Result<bool, String> {
        let resolved = self.resolve(path)?;
        self.refuse_links(path)?;
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("creating {path}: {error}"))?;
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&resolved)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(bytes)
                    .map_err(|error| format!("writing {path}: {error}"))?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(format!("creating {path}: {error}")),
        }
    }

    fn remove(&self, path: &str) -> Result<(), String> {
        let resolved = self.resolve(path)?;
        self.refuse_links(path)?;

        match fs::remove_file(&resolved) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("removing {path}: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permguard-store-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("the scratch directory is created");

        dir
    }

    /// A path that leaves the root is refused, on every operation.
    ///
    /// A workspace is data — a policy repository somebody else wrote — and `..` walked out of the
    /// root unchecked, so a file anywhere on the host could be read and, through `apply`, pushed.
    #[test]
    fn a_path_may_not_leave_the_root() {
        let dir = scratch("escape");
        let inside = dir.join("inside");
        fs::create_dir_all(&inside).expect("the inner directory is created");
        fs::write(dir.join("outside.txt"), b"secret").expect("the outer file is written");

        let store = FsStore::new(&inside);

        for path in [
            "../outside.txt",
            "a/../../outside.txt",
            "./../outside.txt",
            "/etc/hosts",
        ] {
            assert!(
                store.read(path).is_err(),
                "`{path}` was resolved instead of refused"
            );
            assert!(!store.exists(path), "`{path}` reported as existing");
            assert!(store.write(path, b"x").is_err(), "`{path}` was written");
            assert!(store.list(path).is_err(), "`{path}` was listed");
        }

        // What is inside is still perfectly reachable, `.` and doubled separators included.
        store
            .write("a/b.txt", b"held")
            .expect("a path inside writes");
        assert_eq!(
            store.read("./a//b.txt").expect("reads"),
            Some(b"held".to_vec())
        );
    }

    /// A symbolic link is refused, and not descended through.
    ///
    /// This is how a workspace exfiltrated: a link inside a partition pointed at a file on the
    /// host, and the target was read as a policy and pushed to the ledger.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_not_the_stores_own_file() {
        let dir = scratch("links");
        let inside = dir.join("inside");
        fs::create_dir_all(inside.join("partition")).expect("the partition exists");
        fs::write(dir.join("secret.txt"), b"secret").expect("the outer file is written");
        fs::create_dir_all(dir.join("elsewhere")).expect("the outer directory exists");
        fs::write(dir.join("elsewhere/also.txt"), b"secret").expect("the outer file is written");

        std::os::unix::fs::symlink(
            dir.join("secret.txt"),
            inside.join("partition/linked.cedar"),
        )
        .expect("the link is made");
        std::os::unix::fs::symlink(dir.join("elsewhere"), inside.join("linked-dir"))
            .expect("the link is made");

        let store = FsStore::new(&inside);

        assert!(
            store.read("partition/linked.cedar").is_err(),
            "a linked file was read as the store's own"
        );
        assert!(!store.exists("partition/linked.cedar"));

        // And a linked directory is not reported as a directory, so a walk does not enter it.
        let listed = store.list("").expect("the root lists");
        assert!(
            !listed.iter().any(|(name, _)| name == "linked-dir"),
            "a linked directory was offered to the walk: {listed:?}"
        );
        assert!(
            listed
                .iter()
                .any(|(name, is_dir)| name == "partition" && *is_dir),
            "a real directory must still be listed: {listed:?}"
        );
    }

    /// A link in the **middle** of a path is the same escape one level up.
    ///
    /// Checking only the last component refused `partition/linked.cedar` and let
    /// `linked-dir/anything` through — and `list` was not the only way in: a path is also named
    /// directly, by a case file, a manifest, or a caller. Every operation walks every component.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_part_way_along_a_path_is_refused_too() {
        let dir = scratch("links-midway");
        let inside = dir.join("inside");
        fs::create_dir_all(&inside).expect("the workspace exists");
        fs::create_dir_all(dir.join("elsewhere/deeper")).expect("the outer tree exists");
        fs::write(dir.join("elsewhere/secret.cedar"), b"secret")
            .expect("the outer file is written");

        std::os::unix::fs::symlink(dir.join("elsewhere"), inside.join("linked-dir"))
            .expect("the link is made");

        let store = FsStore::new(&inside);

        // Read, through the link.
        assert!(
            store.read("linked-dir/secret.cedar").is_err(),
            "a file was read through a linked directory"
        );
        assert!(!store.exists("linked-dir/secret.cedar"));
        assert!(
            store.list("linked-dir").is_err(),
            "a linked directory was listed by name"
        );
        assert!(
            store.list("linked-dir/deeper").is_err(),
            "and so was one below it"
        );

        // Write, create and remove, through the same link. Each must leave the outer tree alone.
        assert!(
            store.write("linked-dir/planted.cedar", b"x").is_err(),
            "a file was written outside the root"
        );
        assert!(
            store
                .create_exclusive("linked-dir/planted.cedar", b"x")
                .is_err(),
            "a file was created outside the root"
        );
        assert!(
            store.remove("linked-dir/secret.cedar").is_err(),
            "a file outside the root was removed"
        );
        assert!(
            dir.join("elsewhere/secret.cedar").exists(),
            "the outer file must survive every one of those"
        );
        assert!(
            !dir.join("elsewhere/planted.cedar").exists(),
            "and nothing may be planted beside it"
        );

        // What is genuinely inside still works, at any depth.
        store
            .write("real/deeper/policy.cedar", b"held")
            .expect("a real path writes");
        assert_eq!(
            store.read("real/deeper/policy.cedar").expect("reads"),
            Some(b"held".to_vec())
        );
        store.remove("real/deeper/policy.cedar").expect("removes");
    }
}
