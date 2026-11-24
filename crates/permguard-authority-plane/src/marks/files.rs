// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed marks on the file backend: one JSON file, replaced whole.
//!
//! ```text
//! planes/authority/lists-signed.json     {"lists": {"<list id>": <highest iat signed>}}
//! ```

use std::collections::BTreeMap;

use permguard_host::identity::record::uuid_text;
use permguard_host::storage::Dir;

use super::MarkStore;
use crate::tokens::parse_id;

/// The file the marks are kept in, below the plane's directory.
pub const SIGNED_MARKS: &str = "lists-signed.json";

/// The marks, by list id in hex.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedMarks {
    lists: BTreeMap<String, u64>,
}

/// The marks the volume holds; none when it holds no file or one that does not read, which the
/// fixed lead then covers as before.
fn read_marks(dir: &Dir) -> BTreeMap<[u8; 16], u64> {
    let Ok(Some(bytes)) = dir.read(SIGNED_MARKS) else {
        return BTreeMap::new();
    };
    let Ok(marks) = serde_json::from_slice::<SignedMarks>(&bytes) else {
        return BTreeMap::new();
    };
    marks
        .lists
        .into_iter()
        .filter_map(|(id, iat)| parse_id(&id).map(|id| (id, iat)))
        .collect()
}

/// Writes `marks` whole, replacing the file.
fn write_marks(dir: &Dir, marks: &BTreeMap<[u8; 16], u64>) -> Result<(), String> {
    let held = SignedMarks {
        lists: marks
            .iter()
            .map(|(id, iat)| (uuid_text(id), *iat))
            .collect(),
    };
    let bytes = serde_json::to_vec(&held).map_err(|error| error.to_string())?;
    permguard_host::storage::write::replace_bytes(dir, SIGNED_MARKS, &bytes)
        .map_err(|error| error.to_string())
}

/// The marks of one Authority Plane, on its volume.
#[derive(Debug)]
pub struct FileMarks {
    dir: Dir,
}

impl FileMarks {
    /// The marks kept in `dir`, the plane's directory.
    pub fn new(dir: Dir) -> Self {
        Self { dir }
    }
}

impl MarkStore for FileMarks {
    fn held(&self) -> BTreeMap<[u8; 16], u64> {
        read_marks(&self.dir)
    }

    fn keep(&self, marks: &BTreeMap<[u8; 16], u64>) -> Result<(), String> {
        write_marks(&self.dir, marks)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> Dir {
        let root =
            std::env::temp_dir().join(format!("pg-authority-marks-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        Dir::open(&root).expect("a directory")
    }

    /// The file backend keeps the contract's suite (E30).
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let made = std::sync::atomic::AtomicUsize::new(0);
        super::super::suite::run(&|| {
            let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::sync::Arc::new(FileMarks::new(scratch(&format!("suite-{case}"))))
        });
    }

    /// The marks are a file of the plane's directory: a store opened again holds them.
    #[test]
    fn the_marks_survive_a_restart() {
        let root = scratch("restart").path().to_path_buf();
        FileMarks::new(Dir::open(&root).expect("a directory"))
            .keep(&BTreeMap::from([([3; 16], 300)]))
            .expect("kept");
        assert_eq!(
            FileMarks::new(Dir::open(&root).expect("opened again")).held(),
            BTreeMap::from([([3; 16], 300)])
        );
    }
}
