// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The local object mirror: the same content-addressed layout as the
//! server's — zlib-compressed at rest, digests naming the raw canonical
//! bytes — under a root the caller names (`.permguard/objects` for a
//! workspace, a volume path for a data plane).

use permguard_objects::digest::Digest;
use permguard_objects::{compress, limits};

use crate::store::Store;

// The prefix of a temporary the storage library writes before it publishes.
use permguard_host::storage::dir::TEMP_PREFIX;

fn path_of(root: &str, digest: &Digest) -> String {
    let hex = digest.to_string();
    let hex = &hex["sha256:".len()..];
    format!("{root}/{}/{}", &hex[..2], &hex[2..])
}

/// Stores an object under its digest, never replacing one already there (H-06): the same object
/// is a no-op, and a name holding a different object is refused and left as it was.
pub fn put(store: &dyn Store, root: &str, bytes: &[u8]) -> Result<Digest, String> {
    publish(store, root, bytes).map(|(digest, _)| digest)
}

/// The same, and whether it wrote: `false` when the object was already there.
pub fn publish(store: &dyn Store, root: &str, bytes: &[u8]) -> Result<(Digest, bool), String> {
    let digest = Digest::compute(bytes);
    let path = path_of(root, &digest);
    // Compared as content, not as compressed bytes: two compressors may encode one object
    // differently, and only the object is the identity.
    let holds_this = |stored: &[u8]| {
        compress::inflate(stored, limits::MAX_OBJECT_BYTES).is_ok_and(|held| held == bytes)
    };
    let written = store
        .publish(&path, &compress::deflate(bytes), &holds_this)
        .map_err(|error| format!("local object {digest}: {error}"))?;
    Ok((digest, written))
}

/// Reads one object, decompressed and hash-verified on the way out.
pub fn get(store: &dyn Store, root: &str, digest: &Digest) -> Result<Option<Vec<u8>>, String> {
    match store.read(&path_of(root, digest))? {
        None => Ok(None),
        Some(stored) => {
            let bytes = compress::inflate(&stored, limits::MAX_OBJECT_BYTES)
                .map_err(|_| format!("local object {digest} is corrupt"))?;
            if Digest::compute(&bytes) != *digest {
                return Err(format!("local object {digest} is corrupt"));
            }
            Ok(Some(bytes))
        }
    }
}

/// Whether an object is present.
pub fn has(store: &dyn Store, root: &str, digest: &Digest) -> bool {
    store.exists(&path_of(root, digest))
}

/// Removes one object, answering the stored bytes it freed.
///
/// Removing what is not there is a success — two callers reaching the same
/// conclusion at the same time is not an error — and the path is built from
/// the digest, never taken from a caller, so this cannot reach outside the
/// store's own fanout.
pub fn remove(store: &dyn Store, root: &str, digest: &Digest) -> Result<u64, String> {
    let path = path_of(root, digest);
    let freed = store
        .read(&path)?
        .map(|bytes| bytes.len() as u64)
        .unwrap_or(0);
    store.remove(&path)?;

    Ok(freed)
}

/// Removes every temporary file a publish interrupted by a crash left in the fanout; answers how
/// many.
///
/// Only under the lock of whoever owns the store: a temporary is a publish in flight until the
/// process that made it is gone, and the caller is the one that knows no publish is running.
pub fn sweep_temporaries(store: &dyn Store, root: &str) -> Result<usize, String> {
    let mut swept = 0;
    for (fan, is_dir) in store.list(root)? {
        if !is_dir {
            continue;
        }
        for (rest, is_dir) in store.list(&format!("{root}/{fan}"))? {
            // The storage library's temporaries, and the `*.tmp` of earlier versions.
            if !is_dir && (rest.starts_with(TEMP_PREFIX) || rest.ends_with(".tmp")) {
                store.remove(&format!("{root}/{fan}/{rest}"))?;
                swept += 1;
            }
        }
    }
    Ok(swept)
}

/// Lists every stored digest; a temporary is not one.
pub fn list(store: &dyn Store, root: &str) -> Result<Vec<Digest>, String> {
    let mut digests = Vec::new();
    for (fan, is_dir) in store.list(root)? {
        if !is_dir {
            continue;
        }
        for (rest, is_dir) in store.list(&format!("{root}/{fan}"))? {
            // A temporary's name is not a digest, so it is never listed.
            if is_dir {
                continue;
            }
            if let Ok(digest) = Digest::parse(&format!("sha256:{fan}{rest}")) {
                digests.push(digest);
            }
        }
    }
    Ok(digests)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// The storage contract (H-06), run against the filesystem store's object path — the one a
    /// mirror pull and a workspace build publish through.
    #[test]
    fn local_objects_keep_the_immutable_storage_contract() {
        struct Objects(crate::store::FsStore, std::path::PathBuf);
        impl permguard_host::storage::testing::ImmutableStore for Objects {
            fn publish(
                &self,
                content: &[u8],
            ) -> Result<bool, permguard_host::storage::testing::Refused> {
                use permguard_host::storage::testing::Refused;
                // The store's errors are text; the storage library's corruption reads
                // "corruption: …", and only it does.
                publish(&self.0, "objects", content)
                    .map(|(_, written)| written)
                    .map_err(|error| {
                        if error.contains("corruption: ") {
                            Refused::Corruption(error)
                        } else {
                            Refused::Other(error)
                        }
                    })
            }
            fn path_of(&self, content: &[u8]) -> std::path::PathBuf {
                self.1.join(path_of("objects", &Digest::compute(content)))
            }
            fn read(&self, content: &[u8]) -> Option<Vec<u8>> {
                get(&self.0, "objects", &Digest::compute(content))
                    .ok()
                    .flatten()
            }
        }

        let root = std::env::temp_dir().join(format!(
            "permguard-client-objects-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a root");
        let store = Objects(crate::store::FsStore::new(&root), root);
        let content = b"an object's canonical bytes".to_vec();
        let forged = compress::deflate(b"another object's bytes");
        permguard_host::storage::testing::immutable_contract(&store, &content, &forged);
    }

    /// A temporary a crash left is not listed as an object, and the sweep removes it alone.
    #[test]
    fn a_temporary_is_not_an_object_and_is_swept() {
        let root = std::env::temp_dir().join(format!(
            "permguard-client-temporaries-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a root");
        let store = crate::store::FsStore::new(&root);
        let digest = put(&store, "objects", b"kept").expect("published");
        let hex = digest.to_string();
        let fan = root
            .join("objects")
            .join(&hex["sha256:".len().."sha256:".len() + 2]);
        std::fs::write(
            fan.join(format!("{TEMP_PREFIX}0123456789abcdef")),
            b"partial",
        )
        .expect("a temporary");

        assert_eq!(
            list(&store, "objects").expect("listed"),
            vec![digest.clone()]
        );
        assert_eq!(sweep_temporaries(&store, "objects").expect("swept"), 1);
        assert_eq!(std::fs::read_dir(&fan).expect("the fan").count(), 1);
        assert!(has(&store, "objects", &digest));
    }
}
