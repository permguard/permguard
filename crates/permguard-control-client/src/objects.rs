// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The local object mirror: the same content-addressed layout as the
//! server's — zlib-compressed at rest, digests naming the raw canonical
//! bytes — under a root the caller names (`.permguard/objects` for a
//! workspace, a volume path for a data plane).

use permguard_objects::digest::Digest;
use permguard_objects::{compress, limits};

use crate::store::Store;

fn path_of(root: &str, digest: &Digest) -> String {
    let hex = digest.to_string();
    let hex = &hex["sha256:".len()..];
    format!("{root}/{}/{}", &hex[..2], &hex[2..])
}

/// Stores one object; a no-op when the digest is already present.
pub fn put(store: &dyn Store, root: &str, bytes: &[u8]) -> Result<Digest, String> {
    let digest = Digest::compute(bytes);
    let path = path_of(root, &digest);
    if !store.exists(&path) {
        store.write(&path, &compress::deflate(bytes))?;
    }
    Ok(digest)
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

/// Lists every stored digest.
pub fn list(store: &dyn Store, root: &str) -> Result<Vec<Digest>, String> {
    let mut digests = Vec::new();
    for (fan, is_dir) in store.list(root)? {
        if !is_dir {
            continue;
        }
        for (rest, is_dir) in store.list(&format!("{root}/{fan}"))? {
            if is_dir || rest.ends_with(".tmp") {
                continue;
            }
            if let Ok(digest) = Digest::parse(&format!("sha256:{fan}{rest}")) {
                digests.push(digest);
            }
        }
    }
    Ok(digests)
}
