// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A task mirror's reap candidacy (WP-7.2d, `3-data-plane/3-data-plane-mirrors-notp.md`,
//! contention and reaping).
//!
//! ```text
//! a complete listing of its own task no longer names it
//!   no TOMBSTONE   ─▶ write TOMBSTONE {first_absent_at, task, revision}, audit, keep serving
//!   TOMBSTONE, the grace not yet past since first_absent_at ─▶ keep it
//!   TOMBSTONE, the grace past  ─▶ reap the mirror, audit
//! a listing names it again ─▶ remove TOMBSTONE, audit
//! ```
//!
//! So a mirror is reaped only after two complete listings of its task, at least the grace apart,
//! both without it: never on one listing, however complete. A tombstoned mirror keeps serving what
//! it verified, since an absence from a listing revokes nothing a signed head did not.

use std::path::Path;

use permguard_host::storage::{Dir, write};
use permguard_objects::cbor::{self, Value};

/// The candidacy's file, inside the mirror.
pub const TOMBSTONE: &str = "TOMBSTONE";

/// The record version this build writes and reads.
const VERSION: i64 = 1;

/// A mirror its task no longer lists, since when, and by which task at which revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// When a complete listing first left it out, unix seconds.
    pub first_absent_at: u64,
    /// The task that left it out, `<membership-id>/<task-id>`.
    pub task: String,
    /// That task's revision, the epoch of its manifest.
    pub revision: u64,
}

fn uint(value: u64, what: &str) -> Result<Value, String> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| format!("the tombstone's {what} is out of range"))
}

impl Tombstone {
    /// Canonical CBOR `{1 v: 1, 2 first_absent_at, 3 task, 4 revision}`.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(VERSION)),
            (Value::Int(2), uint(self.first_absent_at, "first absence")?),
            (Value::Int(3), Value::Text(self.task.clone())),
            (Value::Int(4), uint(self.revision, "revision")?),
        ]))
        .map_err(|error| error.to_string())
    }

    /// The record, closed: every label of the version, in order, none other.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let value = cbor::decode_canonical(bytes).map_err(|error| error.to_string())?;
        let Value::Map(pairs) = value else {
            return Err("a tombstone is a map".to_owned());
        };
        match pairs.first() {
            Some((Value::Int(1), Value::Int(version))) if *version == VERSION => {}
            Some((Value::Int(1), Value::Int(version))) => {
                return Err(format!(
                    "a tombstone of version {version}, which this build does not read"
                ));
            }
            _ => return Err("a tombstone names no version first".to_owned()),
        }
        let labels: Vec<&Value> = pairs.iter().map(|(key, _)| key).collect();
        if labels != [1, 2, 3, 4].map(Value::Int).iter().collect::<Vec<_>>() {
            return Err("a tombstone holds exactly labels 1 to 4, in order".to_owned());
        }
        let int = |at: usize, what: &str| match &pairs[at].1 {
            Value::Int(value) if *value >= 0 => Ok(*value as u64),
            _ => Err(format!("the tombstone's {what} is not an unsigned integer")),
        };
        let Value::Text(task) = &pairs[2].1 else {
            return Err("the tombstone's task is not text".to_owned());
        };
        Ok(Self {
            first_absent_at: int(1, "first absence")?,
            task: task.clone(),
            revision: int(3, "revision")?,
        })
    }
}

fn storage(error: impl std::fmt::Display) -> String {
    format!("the mirror's tombstone: {error}")
}

/// The tombstone `mirror` holds, if any.
pub fn read(mirror: &Path) -> Result<Option<Tombstone>, String> {
    let dir = Dir::open(mirror).map_err(storage)?;
    dir.read(TOMBSTONE)
        .map_err(storage)?
        .map(|bytes| Tombstone::decode(&bytes))
        .transpose()
}

/// Writes `tombstone` into `mirror`, durably, replacing any.
pub fn write(mirror: &Path, tombstone: &Tombstone) -> Result<(), String> {
    let dir = Dir::open(mirror).map_err(storage)?;
    write::replace_bytes(&dir, TOMBSTONE, &tombstone.encode()?).map_err(storage)
}

/// Removes `mirror`'s tombstone, durably; whether there was one.
pub fn clear(mirror: &Path) -> Result<bool, String> {
    let dir = Dir::open(mirror).map_err(storage)?;
    let removed = dir.unlink(TOMBSTONE).map_err(storage)?;
    if removed {
        dir.sync().map_err(storage)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-mirror-tombstone-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    fn held() -> Tombstone {
        Tombstone {
            first_absent_at: 1_700_000_000,
            task: "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/mirror".to_owned(),
            revision: 4,
        }
    }

    /// WP-7.2d: a tombstone round trips through its file, is closed to its four labels, names
    /// another version as one, and goes when cleared.
    #[test]
    fn a_tombstone_round_trips_is_closed_and_is_cleared() {
        let mirror = scratch("round-trip");
        assert_eq!(read(&mirror).expect("reads"), None);
        write(&mirror, &held()).expect("written");
        assert_eq!(read(&mirror).expect("reads"), Some(held()));

        let bytes = held().encode().expect("encodes");
        let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("canonical") else {
            panic!("a map");
        };
        assert_eq!(pairs.len(), 4);
        let reencode =
            |pairs: Vec<(Value, Value)>| cbor::encode(&Value::Map(pairs)).expect("encodes");
        let mut extra = pairs.clone();
        extra.push((Value::Int(5), Value::Int(0)));
        assert!(Tombstone::decode(&reencode(extra)).is_err(), "a label more");
        let mut short = pairs.clone();
        short.pop();
        assert!(Tombstone::decode(&reencode(short)).is_err(), "a label less");
        let mut negative = pairs.clone();
        negative[1].1 = Value::Int(-1);
        assert!(
            Tombstone::decode(&reencode(negative)).is_err(),
            "a first absence before the epoch"
        );
        pairs[0].1 = Value::Int(2);
        let other = Tombstone::decode(&reencode(pairs)).expect_err("another version");
        assert!(other.contains("version 2"), "{other}");

        assert!(clear(&mirror).expect("cleared"));
        assert_eq!(read(&mirror).expect("reads"), None);
        assert!(!clear(&mirror).expect("nothing to clear"));
    }
}
