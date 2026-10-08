// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A CBOR sequence file (RFC 8742): canonical items one after another, each appended whole and
//! flushed before the append returns (WP-3.6).
//!
//! | Step     | Protocol                                                                                   |
//! | -------- | ------------------------------------------------------------------------------------------ |
//! | append   | open, or create and flush the parent → write at the end → flush; a failure cuts its own bytes back off |
//! | read     | items until the end; an incomplete final item shorter than any item can be is a torn write |
//! | recover  | read, then cut a torn final item with [`write::truncate`]                                  |
//!
//! An item that does not decode, or an incomplete one with at least `max_item` bytes after its
//! start, is corruption: a damaged length must not pass for a torn write and cut what follows it.

use std::io::Write as _;

use permguard_objects::cbor::{self, CborError, Value};

use super::write;
use super::{Dir, Result, StorageError};

/// What a sequence file holds.
#[derive(Debug, Default)]
pub struct Sequence {
    /// The whole items, in order.
    pub items: Vec<Value>,
    /// How many bytes the whole items take; past it is a torn final item.
    pub complete: usize,
    /// How many bytes the file holds.
    pub len: usize,
}

/// Appends `bytes`, one canonical item, to the sequence `name` below `dir`, creating it when
/// absent, and flushes it. A write or flush that fails cuts what reached the file back off, best
/// effort; opening the file with [`recover`] cuts it otherwise.
pub fn append(dir: &Dir, name: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.child_path(name);
    let mut file = match dir.open_write(name) {
        Ok(file) => file,
        Err(StorageError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            let file = dir.create_exclusive(name)?;
            dir.sync()?;
            file
        }
        Err(error) => return Err(error),
    };
    let end = file
        .metadata()
        .map_err(|source| StorageError::Io {
            what: format!("measuring {}", path.display()),
            source,
        })?
        .len();
    let written = (|| {
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(end)).map_err(|source| {
            StorageError::Io {
                what: format!("seeking {}", path.display()),
                source,
            }
        })?;
        permguard_core::fault::write(&path, bytes.len(), || file.write_all(bytes)).map_err(
            |source| StorageError::Io {
                what: format!("appending to {}", path.display()),
                source,
            },
        )?;
        write::flush(dir, name, &file)
    })();
    if let Err(error) = written {
        let _ = write::truncate(dir, name, &file, end);
        return Err(error);
    }
    Ok(())
}

/// Reads the sequence `name` below `dir`; an absent file is an empty sequence. `max_item` is the
/// most bytes one item may take.
pub fn read(dir: &Dir, name: &str, max_item: usize) -> Result<Sequence> {
    let bytes = dir.read(name)?.unwrap_or_default();
    let mut items = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match cbor::decode_canonical_prefix(&bytes[at..]) {
            Ok((value, taken)) if taken <= max_item => {
                items.push(value);
                at += taken;
            }
            Ok((_, taken)) => {
                return Err(StorageError::Corruption(format!(
                    "{} holds an item of {taken} bytes at offset {at}, more than {max_item}",
                    dir.child_path(name).display()
                )));
            }
            Err(CborError::Truncated) if bytes.len() - at < max_item => break,
            Err(error) => {
                return Err(StorageError::Corruption(format!(
                    "{} holds bytes that are not an item at offset {at}: {error}",
                    dir.child_path(name).display()
                )));
            }
        }
    }
    Ok(Sequence {
        items,
        complete: at,
        len: bytes.len(),
    })
}

/// Reads the sequence and cuts a torn final item, durably.
pub fn recover(dir: &Dir, name: &str, max_item: usize) -> Result<Sequence> {
    let mut sequence = read(dir, name, max_item)?;
    if sequence.complete != sequence.len {
        let file = dir.open_write(name)?;
        write::truncate(dir, name, &file, sequence.complete as u64)?;
        tracing::warn!(
            event.name = "storage.torn_item_cut",
            component = "host",
            file = %dir.child_path(name).display(),
            bytes = sequence.len - sequence.complete,
            "a torn item was cut from the end of a sequence file"
        );
        sequence.len = sequence.complete;
    }
    Ok(sequence)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-sequence-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Dir::open(&path).expect("opens")
    }

    fn item(text: &str) -> Vec<u8> {
        cbor::encode(&Value::Text(text.to_owned())).expect("encodes")
    }

    #[test]
    fn items_are_appended_read_back_and_a_torn_one_is_cut() {
        let dir = scratch("torn");
        append(&dir, "seq", &item("one")).expect("appended");
        append(&dir, "seq", &item("two")).expect("appended");
        let whole = std::fs::read(dir.child_path("seq")).expect("read");
        let mut torn = whole.clone();
        torn.extend_from_slice(&item("three")[..2]);
        std::fs::write(dir.child_path("seq"), &torn).expect("torn");
        let read_back = read(&dir, "seq", 64).expect("reads");
        assert_eq!(read_back.items.len(), 2);
        assert_eq!(read_back.complete, whole.len());
        let recovered = recover(&dir, "seq", 64).expect("recovers");
        assert_eq!(recovered.items.len(), 2);
        assert_eq!(std::fs::read(dir.child_path("seq")).expect("read"), whole);
        let _ = std::fs::remove_dir_all(dir.path());
    }

    #[test]
    fn a_damaged_length_or_an_oversized_item_is_corruption() {
        let dir = scratch("damaged");
        let mut damaged = vec![0x5a, 0x7f, 0xff, 0xff, 0xff];
        damaged.resize(80, 0);
        std::fs::write(dir.child_path("seq"), &damaged).expect("damaged");
        assert!(matches!(
            recover(&dir, "seq", 64),
            Err(StorageError::Corruption(_))
        ));
        assert_eq!(std::fs::read(dir.child_path("seq")).expect("read"), damaged);
        std::fs::write(dir.child_path("big"), item(&"x".repeat(100))).expect("written");
        assert!(matches!(
            read(&dir, "big", 64),
            Err(StorageError::Corruption(_))
        ));
        let _ = std::fs::remove_dir_all(dir.path());
    }

    #[test]
    fn a_failed_flush_leaves_the_file_as_it_was() {
        let dir = scratch("failed");
        append(&dir, "seq", &item("one")).expect("appended");
        let before = std::fs::read(dir.child_path("seq")).expect("read");
        {
            let _failing = permguard_core::fault::inject(
                dir.path(),
                permguard_core::fault::Fault::FsyncTimes { remaining: 1 },
            );
            append(&dir, "seq", &item("two")).expect_err("not durable");
        }
        assert_eq!(std::fs::read(dir.child_path("seq")).expect("read"), before);
        let _ = std::fs::remove_dir_all(dir.path());
    }
}
