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
//! Moving `CURSOR_KEY` to `CURSOR_KEY.previous` and writing a new one rotates it: new offsets are
//! issued under the new key and outstanding ones keep working until the previous file is removed.
//! Removing `CURSOR_KEY` has a new one minted and invalidates every outstanding offset at once,
//! which is a legitimate thing to do deliberately. Writing other bytes in place, with no previous
//! file naming the old ones, is refused: `CURSOR_KEY.witness` holds the witness of the key in
//! use, and a key replaced in silence does not match it (WP-3.3). Both key files are read, and
//! only the first is ever written to.
//!
//! The key is the root the cursor keys are derived from, one per API and resource on this Host:
//! `derive_host_local(root, host_id, stream.cursor, host_id, <api>/<resource>, 1)`.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use permguard_stream::CursorKey;

/// The file holding the key offsets are issued under.
pub const KEY_FILE: &str = "CURSOR_KEY";
/// The file holding the previous key, still accepted while it exists.
pub const PREVIOUS_KEY_FILE: &str = "CURSOR_KEY.previous";
/// How many bytes a fresh key is.
pub const KEY_BYTES: usize = 32;

/// The file holding the witness of [`KEY_FILE`] (WP-3.3).
pub const WITNESS_FILE: &str = "CURSOR_KEY.witness";

/// The version of the cursor keys derived from the root (WP-3.3): a rotation replaces the root
/// as the module says, it never changes the version.
const KEY_VERSION: u64 = 1;

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

/// The cursor keys of one API on this Host: per resource, `derive_host_local(root, host_id,
/// stream.cursor, host_id, <api>/<resource>, 1)` from the store's root, and from the previous
/// root while a rotation keeps it (WP-3.3, owner decision of 2026-10-08). Derived once per
/// resource and kept, so a read does no I/O; never shows a root or a key.
#[derive(Clone)]
pub struct CursorKeys {
    inner: std::sync::Arc<Keys>,
}

struct Keys {
    issuing: zeroize::Zeroizing<Vec<u8>>,
    previous: Option<zeroize::Zeroizing<Vec<u8>>>,
    host_id: [u8; 16],
    api: String,
    derived: std::sync::Mutex<std::collections::BTreeMap<String, CursorKey>>,
}

impl std::fmt::Debug for CursorKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "CursorKeys({}, redacted)", self.inner.api)
    }
}

impl CursorKeys {
    /// The key cursors of `resource` are sealed and opened under.
    pub fn for_resource(&self, resource: &str) -> Result<CursorKey> {
        let mut derived = self
            .inner
            .derived
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(key) = derived.get(resource) {
            return Ok(key.clone());
        }
        let scoped = format!("{}/{resource}", self.inner.api);
        let derive = |root: &[u8]| -> Result<zeroize::Zeroizing<[u8; 32]>> {
            let version = permguard_host::secrets::KeyVersion::new(KEY_VERSION)
                .ok_or_else(|| anyhow::anyhow!("the cursor key version"))?;
            permguard_host::secrets::HostLocal::new(
                permguard_host::secrets::Root::from_material(root, version)
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
                self.inner.host_id,
            )
            .key(permguard_host::secrets::HostPurpose::StreamCursor, &scoped)
            .map_err(|error| anyhow::anyhow!("{error}"))
        };
        let issuing = derive(&self.inner.issuing)?;
        let previous = self
            .inner
            .previous
            .as_deref()
            .map(|root| derive(root))
            .transpose()?;
        let accepted: Vec<&[u8]> = previous.iter().map(|key| &key[..]).collect();
        let key =
            CursorKey::new(&issuing[..], &accepted).map_err(|error| anyhow::anyhow!("{error}"))?;
        derived.insert(resource.to_owned(), key.clone());
        Ok(key)
    }
}

impl CursorKeys {
    /// The cursor keys of `api` on `host_id` from `root` already in hand, with no previous root:
    /// for a composition that holds its root elsewhere, and for tests.
    pub fn from_root(root: &[u8], host_id: [u8; 16], api: &str) -> Result<Self> {
        if root.len() < permguard_stream::cursor::MIN_KEY_BYTES {
            anyhow::bail!(
                "a cursor root is at least {} bytes",
                permguard_stream::cursor::MIN_KEY_BYTES
            );
        }
        Ok(Self {
            inner: std::sync::Arc::new(Keys {
                issuing: zeroize::Zeroizing::new(root.to_vec()),
                previous: None,
                host_id,
                api: api.to_owned(),
                derived: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            }),
        })
    }
}

/// The cursor keys of `api` on this Host, from the store's witnessed root.
pub fn load(directory: &Path, host_id: [u8; 16], api: &str) -> Result<CursorKeys> {
    let (issuing, previous) = load_root(directory)?;
    Ok(CursorKeys {
        inner: std::sync::Arc::new(Keys {
            issuing: zeroize::Zeroizing::new(issuing),
            previous: previous.map(zeroize::Zeroizing::new),
            host_id,
            api: api.to_owned(),
            derived: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }),
    })
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::path::PathBuf;

    use super::*;
    use permguard_stream::{Cursor, CursorError};

    const HOST: [u8; 16] = [1; 16];

    /// The key of the tests' resource, `acme/main`, under `api`.
    fn key(dir: &Path, what: &str) -> CursorKey {
        load(dir, HOST, "api")
            .expect(what)
            .for_resource("acme/main")
            .expect(what)
    }

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
        let first = key(&dir, "a key is created");
        let token = Cursor::beginning("api", "acme/main", "f", None)
            .seal(&first)
            .expect("it seals");

        // A "restart": the key is read from disk rather than minted again.
        let second = key(&dir, "the key is read back");
        assert!(
            Cursor::open(&token, &second, "api", "acme/main", "f").is_ok(),
            "a restart does not invalidate every consumer's position"
        );
    }

    #[test]
    fn a_rotation_keeps_outstanding_offsets_working_while_the_previous_key_is_kept() {
        let dir = scratch("rotate");
        let before = key(&dir, "a key is created");
        let outstanding = Cursor::beginning("api", "acme/main", "f", None)
            .seal(&before)
            .expect("it seals");

        // The rotation: the old bytes move aside, and a new key is minted in their place.
        let old = fs::read(dir.join(KEY_FILE)).expect("the key is there");
        fs::write(dir.join(PREVIOUS_KEY_FILE), &old).expect("the previous key is kept");
        fs::remove_file(dir.join(KEY_FILE)).expect("the key is replaced");
        let after = key(&dir, "a new key is created");

        assert!(
            Cursor::open(&outstanding, &after, "api", "acme/main", "f").is_ok(),
            "a consumer mid-export keeps its place across a rotation"
        );
        assert_ne!(old, fs::read(dir.join(KEY_FILE)).expect("read"));
    }

    #[test]
    fn a_rotation_without_a_previous_key_invalidates_outstanding_offsets() {
        let dir = scratch("hard-rotate");
        let before = key(&dir, "a key is created");
        let outstanding = Cursor::beginning("api", "acme/main", "f", None)
            .seal(&before)
            .expect("it seals");

        fs::remove_file(dir.join(KEY_FILE)).expect("the key is replaced");
        let after = key(&dir, "a new key is created");

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

        let refused = load(&dir, HOST, "api").expect_err("a short key is a searchable key");
        assert!(refused.to_string().contains("at least"), "{refused}");
    }

    #[cfg(unix)]
    #[test]
    fn a_minted_key_is_readable_by_its_owner_and_nobody_else() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch("mode");
        key(&dir, "a key is created");
        let mode = fs::metadata(dir.join(KEY_FILE))
            .expect("the key is there")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o600);
    }

    /// WP-3.3: a root replaced in silence is refused; the documented rotations are not.
    #[test]
    fn a_root_swapped_in_silence_is_refused_by_its_witness() {
        let dir = scratch("swapped");
        key(&dir, "a key is created");
        fs::write(dir.join(KEY_FILE), [7u8; KEY_BYTES]).expect("swapped");
        let refused = load(&dir, HOST, "api").expect_err("refused");
        assert!(format!("{refused:#}").contains("in silence"), "{refused:#}");
    }

    /// WP-3.3: each API and each resource has its own key, and so does each Host, from one root.
    #[test]
    fn the_cursor_key_is_derived_per_api_resource_and_host() {
        let dir = scratch("derived");
        let decisions = load(&dir, HOST, "decisions")
            .expect("the keys")
            .for_resource("acme/main")
            .expect("a key");
        let token = Cursor::beginning("api", "acme/main", "f", None)
            .seal(&decisions)
            .expect("it seals");
        for other in [
            load(&dir, HOST, "events")
                .expect("the keys")
                .for_resource("acme/main"),
            load(&dir, HOST, "decisions")
                .expect("the keys")
                .for_resource("acme/other"),
            load(&dir, [2; 16], "decisions")
                .expect("the keys")
                .for_resource("acme/main"),
        ] {
            assert_eq!(
                Cursor::open(&token, &other.expect("a key"), "api", "acme/main", "f"),
                Err(CursorError::Forged)
            );
        }
        // Never the root itself.
        let root = fs::read(dir.join(KEY_FILE)).expect("the root");
        let under_root = CursorKey::new(&root, &[]).expect("a key");
        assert_eq!(
            Cursor::open(&token, &under_root, "api", "acme/main", "f"),
            Err(CursorError::Forged)
        );
        // Exactly the blueprint's derivation of `<api>/<resource>`.
        let expected = permguard_objects::crypto::kdf::derive_host_local(
            &root,
            &HOST,
            permguard_core::domains::kdf::STREAM_CURSOR,
            &HOST,
            "decisions/acme/main",
            1,
        )
        .expect("derived");
        let reference = CursorKey::new(&expected[..], &[]).expect("a key");
        assert!(Cursor::open(&token, &reference, "api", "acme/main", "f").is_ok());
    }
}
