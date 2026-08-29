// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The secret a read offset is authenticated with.
//!
//! # Why a store has one at all
//!
//! An offset is a position a consumer holds and presents back, and the server keeps nothing. That
//! is what makes any number of independent readers possible. It also means the *only* thing
//! standing between a consumer and a position it was never given is a signature — so the store
//! keeps one key, signs every offset it issues with it, and refuses one that does not verify.
//!
//! # Where it lives, and why not in the key ring
//!
//! Under the store's own directory, as a plain 32-byte secret with owner-only permissions. Not in
//! the signing ring beside the Ed25519 keys, because it is a different kind of secret: the ring's
//! keys are *published* — a verifier needs them — and this one must never leave the process. Two
//! kinds of secret in one directory is how the wrong one gets published.
//!
//! # Rotation
//!
//! Writing a new `CURSOR_KEY` and keeping the previous bytes in `CURSOR_KEY.previous` rotates it:
//! new offsets are issued under the new key and outstanding ones keep working until the previous
//! file is removed. A rotation with no previous file invalidates every outstanding offset at once,
//! which is a legitimate thing to do deliberately and a surprising thing to do by accident — so
//! both files are read, and only the first is ever written to.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use permguard_stream::CursorKey;

/// The file holding the key offsets are issued under.
pub const KEY_FILE: &str = "CURSOR_KEY";
/// The file holding the previous key, still accepted while it exists.
pub const PREVIOUS_KEY_FILE: &str = "CURSOR_KEY.previous";
/// How many bytes a fresh key is.
pub const KEY_BYTES: usize = 32;

/// Reads the store's cursor key, creating one on first use.
///
/// Created rather than demanded, because an offset key is not a trust anchor: nothing outside this
/// process verifies against it, and a deployment that had to provision one before its first read
/// would be provisioning a secret whose only property is that nobody else knows it. What matters
/// is that it is *stable* — which is why it is written to disk rather than minted per start, and
/// why a restart does not invalidate every consumer's position.
pub fn load(directory: &Path) -> Result<CursorKey> {
    let path = directory.join(KEY_FILE);
    let issuing = match fs::read(&path) {
        Ok(held) if held.len() >= permguard_stream::cursor::MIN_KEY_BYTES => held,
        Ok(held) => {
            anyhow::bail!(
                "`{}` holds {} bytes, and an offset signing key is at least {}. Remove it to have \
                 one generated, understanding that every outstanding read offset becomes invalid",
                path.display(),
                held.len(),
                permguard_stream::cursor::MIN_KEY_BYTES
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => mint(&path)?,
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };

    // The previous key, when a rotation left one. Absent is the ordinary case.
    let previous = fs::read(directory.join(PREVIOUS_KEY_FILE)).unwrap_or_default();
    let accepted: Vec<&[u8]> = if previous.len() >= permguard_stream::cursor::MIN_KEY_BYTES {
        vec![previous.as_slice()]
    } else {
        Vec::new()
    };

    CursorKey::new(&issuing, &accepted).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Writes a fresh key, readable by its owner and nobody else.
fn mint(path: &PathBuf) -> Result<Vec<u8>> {
    use ring::rand::SecureRandom as _;

    let mut bytes = vec![0u8; KEY_BYTES];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("this system has no source of randomness"))?;

    // Written to a temporary name and renamed, so a reader never sees a half-written key — and a
    // crash between the two leaves the store with no key rather than a short one.
    let temporary = path.with_extension("writing");
    fs::write(&temporary, &bytes).with_context(|| format!("writing {}", temporary.display()))?;
    restrict(&temporary)?;
    fs::rename(&temporary, path).with_context(|| format!("writing {}", path.display()))?;

    Ok(bytes)
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(path: &Path) -> Result<()> {
    // No mode bits to set. The file inherits the store directory's own access control, which is
    // what protects everything else the store holds.
    let _ = path;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use permguard_stream::{Cursor, CursorError};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-cursor-key-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("the directory is created");

        dir
    }

    #[test]
    fn a_key_is_created_once_and_survives_a_restart() {
        let dir = scratch("stable");
        let first = load(&dir).expect("a key is created");
        let token = Cursor::beginning("api", "acme/main", "f", None)
            .seal(&first)
            .expect("it seals");

        // A "restart": the key is read from disk rather than minted again.
        let second = load(&dir).expect("the key is read back");
        assert!(
            Cursor::open(&token, &second, "api", "acme/main", "f").is_ok(),
            "a restart does not invalidate every consumer's position"
        );
    }

    #[test]
    fn a_rotation_keeps_outstanding_offsets_working_while_the_previous_key_is_kept() {
        let dir = scratch("rotate");
        let before = load(&dir).expect("a key is created");
        let outstanding = Cursor::beginning("api", "acme/main", "f", None)
            .seal(&before)
            .expect("it seals");

        // The rotation: the old bytes move aside, and a new key is minted in their place.
        let old = fs::read(dir.join(KEY_FILE)).expect("the key is there");
        fs::write(dir.join(PREVIOUS_KEY_FILE), &old).expect("the previous key is kept");
        fs::remove_file(dir.join(KEY_FILE)).expect("the key is replaced");
        let after = load(&dir).expect("a new key is created");

        assert!(
            Cursor::open(&outstanding, &after, "api", "acme/main", "f").is_ok(),
            "a consumer mid-export keeps its place across a rotation"
        );
        assert_ne!(old, fs::read(dir.join(KEY_FILE)).expect("read"));
    }

    #[test]
    fn a_rotation_without_a_previous_key_invalidates_outstanding_offsets() {
        let dir = scratch("hard-rotate");
        let before = load(&dir).expect("a key is created");
        let outstanding = Cursor::beginning("api", "acme/main", "f", None)
            .seal(&before)
            .expect("it seals");

        fs::remove_file(dir.join(KEY_FILE)).expect("the key is replaced");
        let after = load(&dir).expect("a new key is created");

        assert_eq!(
            Cursor::open(&outstanding, &after, "api", "acme/main", "f"),
            Err(CursorError::Forged),
            "a hard rotation is a deliberate invalidation, and it is not silent"
        );
    }

    #[test]
    fn a_key_too_short_to_authenticate_with_is_refused_rather_than_used() {
        let dir = scratch("short");
        fs::write(dir.join(KEY_FILE), b"short").expect("written");

        let refused = load(&dir).expect_err("a short key is a searchable key");
        assert!(refused.to_string().contains("at least"), "{refused}");
    }

    #[cfg(unix)]
    #[test]
    fn a_minted_key_is_readable_by_its_owner_and_nobody_else() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch("mode");
        load(&dir).expect("a key is created");
        let mode = fs::metadata(dir.join(KEY_FILE))
            .expect("the key is there")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o600);
    }
}
