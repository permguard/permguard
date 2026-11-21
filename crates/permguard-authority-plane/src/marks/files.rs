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
