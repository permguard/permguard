// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Immutable content, published without replacement, and views, replaced atomically.
//!
//! # Immutable content (H-06)
//!
//! | Step                                | Crash here leaves                                   | Recovery                        |
//! | ----------------------------------- | --------------------------------------------------- | ------------------------------- |
//! | create temp `O_EXCL`, no-follow     | an empty temporary                                  | swept                           |
//! | write, flush                        | a temporary, partial or whole                       | swept                           |
//! | read back and verify                | a temporary                                         | swept                           |
//! | hard link temp → name (no replace)  | the name, complete, and the temporary               | swept; the name is published    |
//! | unlink temp, flush parent           | the name                                            | nothing to do                   |
//!
//! The name either does not exist or holds exactly what was verified: there is no step at which a
//! reader can see a partial file under it, and no step at which an existing name is replaced. When
//! the name already exists the existing content is compared: the same content is a success that
//! writes nothing — not even a new inode — and different content is [`StorageError::Corruption`],
//! with the existing file left byte-for-byte as it was.
//!
//! A success is a durable claim either way. The existing file and its directory are flushed before
//! [`Published::AlreadyThere`] is answered: the name may be one another writer linked a moment ago
//! and has not flushed yet, or one whose directory flush failed for the writer that linked it, and
//! a caller that goes on to point a ref at it must not point at something a power loss takes away.
//!
//! # Replaceable view
//!
//! A sibling temporary is written and flushed, renamed over the view, and the directory flushed: a
//! reader sees the old view or the new one, never a mixture.

use std::io::Write as _;

use super::dir::{Dir, temp_name};
use super::format::{self, Format};
use super::{Result, StorageError, crash::point, durability, io};

/// What publishing an immutable name did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// The content was written and published under the name.
    Written,
    /// The name already held this content; nothing was written.
    AlreadyThere,
}

/// Publishes immutable `content` as `name` below `dir`, never replacing anything.
///
/// `verify` checks the bytes as read back from the flushed temporary file — a content address
/// checks their digest — and a temporary that does not verify is never published. `same` decides
/// whether an existing file under `name` holds this content: for a compressed object, after
/// decompression.
pub fn publish_immutable(
    dir: &Dir,
    name: &str,
    content: &[u8],
    verify: &dyn Fn(&[u8]) -> bool,
    same: &dyn Fn(&[u8]) -> bool,
) -> Result<Published> {
    if let Some(existing) = dir.read(name)? {
        return judge(dir, name, &existing, same);
    }

    let temp = temp_name();
    let outcome = publish_through(dir, name, &temp, content, verify, same);
    if outcome.is_err() {
        // Best effort: a temporary left behind is swept on the next open, and an error here would
        // hide the one that matters.
        let _ = dir.unlink(&temp);
    }
    outcome
}

fn publish_through(
    dir: &Dir,
    name: &str,
    temp: &str,
    content: &[u8],
    verify: &dyn Fn(&[u8]) -> bool,
    same: &dyn Fn(&[u8]) -> bool,
) -> Result<Published> {
    let path = dir.child_path(temp);
    let mut file = dir.create_exclusive(temp)?;
    point("immutable.temp_created");
    permguard_core::fault::write(&path, content.len(), || file.write_all(content))
        .map_err(io(format!("writing {}", path.display())))?;
    point("immutable.temp_written");
    permguard_core::fault::sync(&path, || file.sync_all())
        .map_err(durability(format!("flushing {}", path.display())))?;
    drop(file);
    point("immutable.temp_flushed");

    let written = dir.read(temp)?.ok_or_else(|| vanished(dir, temp))?;
    if !verify(&written) {
        return Err(StorageError::Corruption(format!(
            "the bytes written for {} do not verify",
            dir.child_path(name).display()
        )));
    }

    if !dir.link(temp, name)? {
        // Somebody published it between the first look and now: the same content is a success,
        // other content is corruption — and either way the existing file is untouched.
        let existing = dir.read(name)?.ok_or_else(|| vanished(dir, name))?;
        dir.unlink(temp)?;
        return judge(dir, name, &existing, same);
    }
    point("immutable.linked");
    dir.unlink(temp)?;
    point("immutable.temp_removed");
    dir.sync()?;
    point("immutable.parent_flushed");

    Ok(Published::Written)
}

/// A file this publish was relying on disappeared under it: somebody else removed it, which is
/// an I/O failure to retry, not a statement about its content.
fn vanished(dir: &Dir, name: &str) -> StorageError {
    StorageError::Io {
        what: format!(
            "{} was removed while it was being published",
            dir.child_path(name).display()
        ),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    }
}

fn judge(
    dir: &Dir,
    name: &str,
    existing: &[u8],
    same: &dyn Fn(&[u8]) -> bool,
) -> Result<Published> {
    if same(existing) {
        dir.sync_file(name)?;
        dir.sync()?;
        return Ok(Published::AlreadyThere);
    }
    Err(StorageError::Corruption(format!(
        "{} already holds different content under the same name; it is left as it was",
        dir.child_path(name).display()
    )))
}

/// Replaces the view `name` below `dir` with `body`, atomically, as a whole file of `format`.
pub fn replace_view(dir: &Dir, name: &str, format: Format, body: &[u8]) -> Result<()> {
    replace_through(dir, name, format::encode_file(format, 0, body))
}

/// Replaces the file `name` below `dir` with exactly `bytes`, atomically, with no header of this
/// library's: the same temporary, flush, rename and directory flush as a view, for a store whose
/// bytes on disk are fixed by a layout older than the library (WP-1.11). A reader sees the old
/// file or the new one, never a mixture.
pub fn replace_bytes(dir: &Dir, name: &str, bytes: &[u8]) -> Result<()> {
    replace_through(dir, name, bytes.to_vec())
}

fn replace_through(dir: &Dir, name: &str, bytes: Vec<u8>) -> Result<()> {
    let temp = temp_name();
    let outcome = (|| {
        let path = dir.child_path(&temp);
        let mut file = dir.create_exclusive(&temp)?;
        permguard_core::fault::write(&path, bytes.len(), || file.write_all(&bytes))
            .map_err(io(format!("writing {}", path.display())))?;
        point("view.temp_written");
        permguard_core::fault::sync(&path, || file.sync_all())
            .map_err(durability(format!("flushing {}", path.display())))?;
        drop(file);
        point("view.temp_flushed");
        dir.rename(&temp, name)?;
        point("view.renamed");
        dir.sync()?;
        point("view.parent_flushed");
        Ok(())
    })();
    if outcome.is_err() {
        let _ = dir.unlink(&temp);
    }
    outcome
}

/// Flushes `file`, an open regular file `name` below `dir`, through the fault shim: what a store
/// that appends to a file of its own format calls after each record, instead of a flush of its
/// own (WP-1.11). The file's data and its length reach the medium before this returns.
pub fn flush(dir: &Dir, name: &str, file: &std::fs::File) -> Result<()> {
    let path = dir.child_path(name);
    permguard_core::fault::sync(&path, || file.sync_all())
        .map_err(durability(format!("flushing {}", path.display())))
}

/// Cuts `file`, an open regular file `name` below `dir`, to `keep` bytes and flushes it: how a
/// store of its own format removes a torn tail its reader found (WP-1.11). Which bytes are the
/// tail is the format's judgement; cutting them durably is the library's.
pub fn truncate(dir: &Dir, name: &str, file: &std::fs::File, keep: u64) -> Result<()> {
    set_length(dir, name, file, keep)
}

/// Sets `file`, an open regular file `name` below `dir`, to exactly `length` bytes and flushes
/// it: shorter cuts the tail, longer extends it with zeros, as a reserve a store keeps aside is
/// sized (WP-1.11).
pub fn set_length(dir: &Dir, name: &str, file: &std::fs::File, length: u64) -> Result<()> {
    let path = dir.child_path(name);
    file.set_len(length)
        .map_err(io(format!("sizing {} to {length} bytes", path.display())))?;
    flush(dir, name, file)
}

/// [`publish_immutable`], charged to `scope`: the content's bytes and one file are reserved before
/// anything is written, and only what was written is counted; content already there costs nothing.
pub fn publish_immutable_in(
    scope: &crate::storage::quota::Scope,
    dir: &Dir,
    name: &str,
    content: &[u8],
    verify: &dyn Fn(&[u8]) -> bool,
    same: &dyn Fn(&[u8]) -> bool,
) -> Result<Published> {
    let reservation = scope.reserve(content.len() as u64, 1)?;
    let published = publish_immutable(dir, name, content, verify, same)?;
    if published == Published::Written {
        reservation.land(content.len() as u64, 1);
    }

    Ok(published)
}

/// [`replace_view`], charged to `scope`: the whole new file and its temporary's inode are reserved
/// before anything is written; once it lands, the view it replaced is freed.
pub fn replace_view_in(
    scope: &crate::storage::quota::Scope,
    dir: &Dir,
    name: &str,
    format: Format,
    body: &[u8],
) -> Result<()> {
    let length = format::encode_file(format, 0, body).len() as u64;
    let old = std::fs::symlink_metadata(dir.child_path(name))
        .ok()
        .map(|metadata| metadata.len());
    let reservation = scope.reserve(length, 1)?;
    replace_view(dir, name, format, body)?;
    reservation.land(length, u64::from(old.is_none()));
    if let Some(old) = old {
        scope.freed(old, 0)?;
    }

    Ok(())
}

/// The body of the view `name` below `dir`, or `None` when there is none.
pub fn read_view(dir: &Dir, name: &str, format: Format) -> Result<Option<Vec<u8>>> {
    let Some(bytes) = dir.read(name)? else {
        return Ok(None);
    };
    let (_, body) = format::decode_file(&bytes, format)?;
    Ok(Some(body.to_vec()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-write-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Dir::create_root(&path).expect("a scratch directory")
    }

    fn exact(content: &'static [u8]) -> impl Fn(&[u8]) -> bool {
        move |held: &[u8]| held == content
    }

    #[test]
    fn identical_content_is_idempotent_and_keeps_the_inode() {
        let dir = scratch("idempotent");
        let first = publish_immutable(&dir, "obj", b"same", &exact(b"same"), &exact(b"same"));
        assert_eq!(first.expect("published"), Published::Written);
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(dir.child_path("obj"))
                .expect("there")
                .ino()
        };
        let again = publish_immutable(&dir, "obj", b"same", &exact(b"same"), &exact(b"same"));
        assert_eq!(again.expect("idempotent"), Published::AlreadyThere);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let now = std::fs::metadata(dir.child_path("obj"))
                .expect("there")
                .ino();
            assert_eq!(now, inode, "nothing was rewritten");
        }
        assert!(
            dir.names()
                .expect("listed")
                .iter()
                .all(|name| !name.starts_with(".tmp-"))
        );
    }

    /// H-06: the same name with different content is corruption, and the original stays.
    #[test]
    fn different_content_under_an_existing_name_is_corruption_and_the_original_stays() {
        let dir = scratch("corruption");
        publish_immutable(
            &dir,
            "obj",
            b"original",
            &exact(b"original"),
            &exact(b"original"),
        )
        .expect("published");
        let refused = publish_immutable(
            &dir,
            "obj",
            b"impostor",
            &exact(b"impostor"),
            &exact(b"impostor"),
        )
        .expect_err("refused");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert_eq!(
            std::fs::read(dir.child_path("obj")).expect("there"),
            b"original"
        );
    }

    /// Bytes that do not verify once written are never published.
    #[test]
    fn content_that_does_not_verify_is_never_published() {
        let dir = scratch("verify");
        let refused = publish_immutable(&dir, "obj", b"bytes", &|_| false, &exact(b"bytes"))
            .expect_err("refused");
        assert!(matches!(refused, StorageError::Corruption(_)));
        assert!(!dir.exists("obj").expect("asked"));
        assert!(
            dir.names().expect("listed").is_empty(),
            "the temporary is gone too"
        );
    }

    /// Many writers publishing the same name at once: one writes, every other finds it there, and
    /// the file is complete.
    #[test]
    fn concurrent_equal_publishes_are_idempotent() {
        let root = scratch("concurrent").path().to_path_buf();
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let dir = Dir::open(&root).expect("opened");
                    publish_immutable(
                        &dir,
                        "obj",
                        b"content",
                        &exact(b"content"),
                        &exact(b"content"),
                    )
                    .expect("published or already there")
                })
            })
            .collect();
        let outcomes: Vec<Published> = handles
            .into_iter()
            .map(|held| held.join().expect("joined"))
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|held| **held == Published::Written)
                .count(),
            1
        );
        assert_eq!(std::fs::read(root.join("obj")).expect("there"), b"content");
    }

    #[test]
    fn a_view_is_replaced_whole_and_read_back_verified() {
        let dir = scratch("view");
        replace_view(&dir, "state", format::VIEW, b"one").expect("written");
        replace_view(&dir, "state", format::VIEW, b"two").expect("replaced");
        assert_eq!(
            read_view(&dir, "state", format::VIEW).expect("read"),
            Some(b"two".to_vec())
        );
        let mut bytes = std::fs::read(dir.child_path("state")).expect("there");
        bytes[25] ^= 1;
        std::fs::write(dir.child_path("state"), bytes).expect("damaged");
        assert!(matches!(
            read_view(&dir, "state", format::VIEW).expect_err("damaged"),
            StorageError::Corruption(_)
        ));
    }

    /// The idempotent answer is a durable claim too: it flushes the file and the directory, so a
    /// flush that fails is reported instead of a success — the file's alone as much as both.
    #[test]
    fn already_there_is_answered_only_after_a_flush() {
        let dir = scratch("already-flushed");
        publish_immutable(&dir, "obj", b"x", &exact(b"x"), &exact(b"x")).expect("published");
        for scope in [dir.child_path("obj"), dir.path().to_path_buf()] {
            let _guard =
                permguard_core::fault::inject_exact(&scope, permguard_core::fault::Fault::Fsync);
            let refused = publish_immutable(&dir, "obj", b"x", &exact(b"x"), &exact(b"x"))
                .expect_err("the flush failed");
            assert!(
                matches!(refused, StorageError::Durability { .. }),
                "{}: {refused}",
                scope.display()
            );
        }
    }

    /// A failed directory flush after the link is answered as an error, never retried within the
    /// call; a later publish of the same content flushes the entry again and succeeds (decided for
    /// WP-1.2: the bytes were flushed before the link).
    #[test]
    fn a_failed_entry_flush_is_an_error_and_a_later_publish_flushes_it_again() {
        let dir = scratch("entry-flush");
        {
            // One failure only: a retry within the call would succeed, and the call must not.
            let _guard = permguard_core::fault::inject_exact(
                dir.path(),
                permguard_core::fault::Fault::FsyncTimes { remaining: 1 },
            );
            let refused = publish_immutable(&dir, "obj", b"x", &exact(b"x"), &exact(b"x"))
                .expect_err("the entry's flush failed");
            assert!(
                matches!(refused, StorageError::Durability { .. }),
                "{refused}"
            );
        }
        assert_eq!(
            publish_immutable(&dir, "obj", b"x", &exact(b"x"), &exact(b"x")).expect("flushed now"),
            Published::AlreadyThere
        );
    }

    /// An injected flush failure is final: the publish fails, nothing is published and nothing is
    /// retried.
    #[test]
    fn a_failed_flush_publishes_nothing() {
        let dir = scratch("fsync");
        let _guard = permguard_core::fault::inject(dir.path(), permguard_core::fault::Fault::Fsync);
        let refused = publish_immutable(&dir, "obj", b"x", &exact(b"x"), &exact(b"x"))
            .expect_err("the flush failed");
        assert!(
            matches!(refused, StorageError::Durability { .. }),
            "{refused}"
        );
        assert!(!dir.exists("obj").expect("asked"));
    }
}
