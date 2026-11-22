// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`CursorRoots`]: a plain 32-byte secret with owner-only permissions,
//! under the directory of the store it issues positions into.
//!
//! # Rotation
//!
//! Moving `CURSOR_KEY` to `CURSOR_KEY.previous` and writing a new one rotates it: new offsets are
//! issued under the new key and outstanding ones keep working until the previous file is removed.
//! Removing `CURSOR_KEY` has a new one minted and invalidates every outstanding offset at once,
//! which is a legitimate thing to do deliberately. Writing other bytes in place, with no previous
//! file naming the old ones, is refused: `CURSOR_KEY.witness` holds the witness of the key in
//! use, and a key replaced in silence does not match it (WP-3.3). Both key files are read, and
//! only the first is ever written to.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};

use super::{CursorKeys, CursorRoots, Roots};

/// The file holding the key offsets are issued under.
pub const KEY_FILE: &str = "CURSOR_KEY";
/// The file holding the previous key, still accepted while it exists.
pub const PREVIOUS_KEY_FILE: &str = "CURSOR_KEY.previous";
/// How many bytes a fresh key is.
pub const KEY_BYTES: usize = 32;

/// The file holding the witness of [`KEY_FILE`] (WP-3.3).
pub const WITNESS_FILE: &str = "CURSOR_KEY.witness";

/// Reads the store's cursor root, creating one on first use, with the previous root a rotation
/// left; checks it against its witness (WP-3.3).
///
/// Created rather than demanded, because an offset key is not a trust anchor: nothing outside this
/// process verifies against it, and a deployment that had to provision one before its first read
/// would be provisioning a secret whose only property is that nobody else knows it. What matters
/// is that it is *stable* — which is why it is written to disk rather than minted per start, and
/// why a restart does not invalidate every consumer's position.
///
/// The witness catches a root swapped in silence: other bytes under `CURSOR_KEY` are refused
/// unless they follow the rotation this module describes — the previous root moved to
/// `CURSOR_KEY.previous`, or the root removed and minted again.
pub fn load_root(directory: &Path) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let path = directory.join(KEY_FILE);
    let (issuing, minted) = match fs::read(&path) {
        Ok(held) if held.len() >= permguard_stream::cursor::MIN_KEY_BYTES => (held, false),
        Ok(held) => {
            anyhow::bail!(
                "`{}` holds {} bytes, and an offset signing key is at least {}. Remove it to have \
                 one generated, understanding that every outstanding read offset becomes invalid",
                path.display(),
                held.len(),
                permguard_stream::cursor::MIN_KEY_BYTES
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (mint(&path)?, true),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };

    // The previous key, when a rotation left one. Absent is the ordinary case.
    let previous = fs::read(directory.join(PREVIOUS_KEY_FILE))
        .ok()
        .filter(|previous| previous.len() >= permguard_stream::cursor::MIN_KEY_BYTES);

    let witness = permguard_host::secrets::witness_of(&issuing);
    let witness_path = directory.join(WITNESS_FILE);
    match fs::read(&witness_path) {
        Ok(held) if held == witness => {}
        Ok(held) => {
            let rotated = previous
                .as_ref()
                .is_some_and(|previous| permguard_host::secrets::witness_of(previous) == held[..]);
            if !(rotated || minted) {
                anyhow::bail!(
                    "`{}` is not the key `{}` witnesses, and no rotation moved that one to `{}`: \
                     a cursor key replaced in silence is refused",
                    path.display(),
                    witness_path.display(),
                    PREVIOUS_KEY_FILE
                );
            }
            write_witness(directory, &witness)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_witness(directory, &witness)?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", witness_path.display()));
        }
    }

    Ok((issuing, previous))
}

/// The cursor root kept in the files of `directory`.
pub struct FileCursorRoots {
    directory: PathBuf,
    /// One caller at a time reads the root and mints it when there is none.
    asking: Mutex<()>,
}

impl FileCursorRoots {
    /// The root of the store at `directory`; nothing is read or written until it is asked for.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            asking: Mutex::new(()),
        }
    }
}

impl CursorRoots for FileCursorRoots {
    fn roots(&self) -> Result<Roots> {
        let _asking = self
            .asking
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (issuing, previous) = load_root(&self.directory)?;
        Ok(Roots {
            issuing: zeroize::Zeroizing::new(issuing),
            previous: previous.map(zeroize::Zeroizing::new),
        })
    }
}

/// The cursor keys of `api` on this Host, from the store's witnessed root.
pub fn load(directory: &Path, host_id: [u8; 16], api: &str) -> Result<CursorKeys> {
    CursorKeys::open(&FileCursorRoots::new(directory), host_id, api)
}

fn write_witness(directory: &Path, witness: &[u8; 32]) -> Result<()> {
    let dir = permguard_host::storage::Dir::create_root(directory)
        .with_context(|| format!("opening {}", directory.display()))?;
    permguard_host::storage::write::replace_bytes(&dir, WITNESS_FILE, witness)
        .with_context(|| format!("writing {}", directory.join(WITNESS_FILE).display()))
}

/// Writes a fresh key, readable by its owner and nobody else.
fn mint(path: &Path) -> Result<Vec<u8>> {
    use ring::rand::SecureRandom as _;

    let mut bytes = vec![0u8; KEY_BYTES];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("this system has no source of randomness"))?;

    // Written to a temporary and renamed through the storage library (WP-1.11), so a reader never
    // sees a half-written key and a crash between the two leaves the store with no key rather
    // than a short one. The temporary is created readable by its owner alone; the published key
    // is restricted again, as it was.
    let (parent, name) = path
        .parent()
        .zip(path.file_name().and_then(|name| name.to_str()))
        .ok_or_else(|| anyhow::anyhow!("{} has no portable file name", path.display()))?;
    let dir = permguard_host::storage::Dir::create_root(parent)
        .with_context(|| format!("opening {}", parent.display()))?;
    // The witness first: a crash between the two leaves a witness and no key, and the next start
    // mints again; never a key its witness does not name (WP-3.3).
    write_witness(parent, &permguard_host::secrets::witness_of(&bytes))?;
    permguard_host::storage::write::replace_bytes(&dir, name, &bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    restrict(path)?;

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
