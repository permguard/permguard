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
//! Behind [`CursorRoots`], the contract of the store that keeps the root (`3-control-plane/3`
//! Stores): one root a store, minted the first time it is asked for, the same for everything
//! that asks afterwards, so an offset one instance issued verifies at another. Not in the signing
//! ring beside the Ed25519 keys, because it is a different kind of secret: the ring's keys are
//! *published* — a verifier needs them — and this one must never leave the process. Two kinds of
//! secret in one place is how the wrong one gets published.
//!
//! | Backend            | Keeps the root in                                         |
//! | ------------------ | --------------------------------------------------------- |
//! | [`files`], default | `CURSOR_KEY` beside the store it issues positions into    |
//!
//! The key is the root the cursor keys are derived from, one per API and resource on this Host:
//! `derive_host_local(root, host_id, stream.cursor, host_id, <api>/<resource>, 1)`.

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

use anyhow::Result;
use permguard_stream::CursorKey;

pub use files::{
    FileCursorRoots, KEY_BYTES, KEY_FILE, PREVIOUS_KEY_FILE, WITNESS_FILE, load, load_root,
};

/// The version of the cursor keys derived from the root (WP-3.3): a rotation replaces the root
/// as the module says, it never changes the version.
const KEY_VERSION: u64 = 1;

/// The roots a store's cursor keys are derived from.
pub struct Roots {
    /// The root offsets are issued under.
    pub issuing: zeroize::Zeroizing<Vec<u8>>,
    /// The root before it, still accepted while a rotation keeps it.
    pub previous: Option<zeroize::Zeroizing<Vec<u8>>>,
}

/// The store of the root the cursor keys of one evidence store are derived from.
pub trait CursorRoots: Send + Sync {
    /// The root in use, minted when the store keeps none, and the previous one while a rotation
    /// keeps it. A root is minted once: of the callers that find none together one mints, and
    /// every caller, then and afterwards, is answered that root. A root that is there and does
    /// not read, or is not the one its store witnesses, is an error, never a root to mint again.
    fn roots(&self) -> Result<Roots>;
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
    /// How long a cursor issued under these keys is valid (WP-5.5).
    lifetime: std::time::Duration,
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
    /// These keys, their cursors valid `lifetime` after issue (WP-5.5).
    pub fn with_lifetime(self, lifetime: std::time::Duration) -> Self {
        let inner = std::sync::Arc::try_unwrap(self.inner).unwrap_or_else(|shared| Keys {
            lifetime,
            issuing: shared.issuing.clone(),
            previous: shared.previous.clone(),
            host_id: shared.host_id,
            api: shared.api.clone(),
            derived: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        });
        Self {
            inner: std::sync::Arc::new(Keys { lifetime, ..inner }),
        }
    }

    /// How long a cursor issued now is valid.
    pub fn lifetime(&self) -> std::time::Duration {
        self.inner.lifetime
    }

    /// Now, in seconds: what a cursor's expiry is measured against. A clock before the epoch
    /// reads as the end of time, so every cursor is expired rather than none.
    pub fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(u64::MAX, |elapsed| elapsed.as_secs())
    }

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
                lifetime: permguard_stream::cursor::DEFAULT_LIFETIME,
                issuing: zeroize::Zeroizing::new(root.to_vec()),
                previous: None,
                host_id,
                api: api.to_owned(),
                derived: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            }),
        })
    }
}

impl CursorKeys {
    /// The cursor keys of `api` on `host_id`, from the root `roots` keeps.
    pub fn open(roots: &dyn CursorRoots, host_id: [u8; 16], api: &str) -> Result<Self> {
        let Roots { issuing, previous } = roots.roots()?;
        Ok(Self {
            inner: std::sync::Arc::new(Keys {
                lifetime: permguard_stream::cursor::DEFAULT_LIFETIME,
                issuing,
                previous,
                host_id,
                api: api.to_owned(),
                derived: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::path::PathBuf;

    use std::fs;
    use std::path::Path;

    use super::*;
    use permguard_stream::{Cursor, CursorError};

    /// The file backend passes the contract's suite, each case on a directory of its own.
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let made = std::sync::atomic::AtomicUsize::new(0);
        suite::run(&|| {
            let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::sync::Arc::new(FileCursorRoots::new(scratch(&format!("suite-{case}"))))
        });
    }

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

    /// WP-5.5: the lifetime the keys are given is the one a cursor sealed under them carries.
    #[test]
    fn a_cursor_lives_as_long_as_its_keys_say() {
        let keys = CursorKeys::from_root(&[7; 32], HOST, "decisions")
            .expect("the keys")
            .with_lifetime(std::time::Duration::from_secs(10));
        assert_eq!(keys.lifetime(), std::time::Duration::from_secs(10));
        let key = keys.for_resource("acme/main").expect("a key");
        let token = Cursor::beginning("api", "acme/main", "f", None)
            .seal_v2(&key, 1_000, keys.lifetime())
            .expect("it seals");
        assert!(Cursor::open_any(&token, &key, "api", "acme/main", "f", 1_009).is_ok());
        assert_eq!(
            Cursor::open_any(&token, &key, "api", "acme/main", "f", 1_010),
            Err(CursorError::Forged)
        );
        assert!(keys.now() > 1_000);
    }
}
