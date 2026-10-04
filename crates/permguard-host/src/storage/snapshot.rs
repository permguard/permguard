// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The snapshot cache: built from an authoritative journal, replaced atomically, never trusted over
//! it.
//!
//! A snapshot carries the revision and the digest of the authority it was built from. Loading asks
//! for the revision and digest the authority has now: a snapshot that is missing, stale, damaged or
//! of a format this build does not read answers `None`, and the caller rebuilds it — a rebuildable
//! file that does not verify is rebuilt, never surfaced as an error and never believed.

use super::dir::Dir;
use super::format::{self, CHECKSUM_LEN};
use super::write::{read_view, replace_view};
use super::{Rebuildable, Result, StorageError};

/// Writes the snapshot `name` of `body`, built from the authority at `revision` with `source`.
pub fn write(
    dir: &Rebuildable<Dir>,
    name: &str,
    revision: u64,
    source: &[u8; CHECKSUM_LEN],
    body: &[u8],
) -> Result<()> {
    let mut held = Vec::with_capacity(8 + CHECKSUM_LEN + body.len());
    held.extend_from_slice(&revision.to_be_bytes());
    held.extend_from_slice(source);
    held.extend_from_slice(body);
    replace_view(dir.get(), name, format::SNAPSHOT, &held)
}

/// The snapshot `name`, when it was built from the authority at `revision` with `source`.
pub fn load(
    dir: &Rebuildable<Dir>,
    name: &str,
    revision: u64,
    source: &[u8; CHECKSUM_LEN],
) -> Result<Option<Vec<u8>>> {
    let held = match read_view(dir.get(), name, format::SNAPSHOT) {
        Ok(Some(held)) => held,
        Ok(None) | Err(StorageError::Corruption(_) | StorageError::Unsupported(_)) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let Some((head, body)) = held.split_at_checked(8 + CHECKSUM_LEN) else {
        return Ok(None);
    };
    let built_at = u64::from_be_bytes([
        head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7],
    ]);
    if built_at != revision || head[8..] != source[..] {
        return Ok(None);
    }
    Ok(Some(body.to_vec()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_snapshot_is_used_only_at_its_revision_and_a_damaged_one_is_rebuilt() {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-snapshot-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        let dir = Rebuildable::new(Dir::create_root(&path).expect("a root"));
        let source = format::checksum(b"journal head");
        write(&dir, "view", 7, &source, b"materialized").expect("written");

        assert_eq!(
            load(&dir, "view", 7, &source).expect("read"),
            Some(b"materialized".to_vec())
        );
        assert_eq!(load(&dir, "view", 8, &source).expect("read"), None, "stale");
        assert_eq!(
            load(&dir, "view", 7, &format::checksum(b"other")).expect("read"),
            None
        );

        let mut bytes = std::fs::read(path.join("view")).expect("there");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(path.join("view"), bytes).expect("damaged");
        assert_eq!(
            load(&dir, "view", 7, &source).expect("read"),
            None,
            "rebuilt, not believed"
        );
    }
}
