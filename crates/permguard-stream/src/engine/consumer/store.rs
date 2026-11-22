// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where a consumer's runs rest (iteration 03, WP-27.4).
//!
//! The consumer is one on every backend: what a batch must be to be admitted, what a fork is,
//! what retention deletes and what a read answers are its own and written once. Where the bytes
//! of a run rest is [`RunStore`]; how the runs of a consumer are found and one of them is opened
//! is [`Runs`].
//!
//! | Backend                 | Keeps a consumer's runs in                                 |
//! | ----------------------- | ---------------------------------------------------------- |
//! | [`FileRuns`], default   | `consumer/<resource>/<producer>/<run>/`, as the module says |
//!
//! A run is its journal of frames, its views, kept whole and replaced, and its shelves of
//! immutable files, the batches and the ring statements, each published once.

use permguard_host::storage::journal::{Frame, Journal, Options};
use permguard_host::storage::write::{Published, publish_immutable, read_view, replace_view};
use permguard_host::storage::{Dir, StorageError, format};

use super::super::StreamError;

/// What a run holds besides its journal, read without opening it: what a listing, a frontier
/// and a read of a batch or a statement need.
pub trait RunFiles: Send {
    /// The view `name`, whole.
    fn view(&self, name: &str) -> Result<Option<Vec<u8>>, StreamError>;

    /// The file `name` of the shelf `shelf`.
    fn read(&self, shelf: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError>;

    /// The names on the shelf `shelf`.
    fn names(&self, shelf: &str) -> Result<Vec<String>, StreamError>;
}

/// Where one run's records, views and immutable files rest. A run is opened for one holder at
/// a time: the consumer holds it while it reads or writes it.
pub trait RunStore: RunFiles {
    /// Every frame of the journal, in order.
    fn frames(&self) -> Result<Vec<Frame>, StreamError>;

    /// The frames from `index` on.
    fn frames_from(&self, index: u64) -> Result<Vec<Frame>, StreamError>;

    /// The index of the first frame kept.
    fn first_index(&self) -> u64;

    /// The index the next frame gets.
    fn next_index(&self) -> u64;

    /// Where a prefix deletion may end: the first index of each part the journal is kept in.
    fn segment_starts(&self) -> Vec<u64>;

    /// Appends a frame, durably; answers its index.
    fn append(&mut self, kind: u16, payload: &[u8]) -> Result<u64, StreamError>;

    /// Removes the frames below `below`, at one of [`RunStore::segment_starts`]; answers where
    /// the journal now starts.
    fn drop_prefix(&mut self, below: u64) -> Result<u64, StreamError>;

    /// Replaces the view `name`.
    fn replace_view(&self, name: &str, bytes: &[u8]) -> Result<(), StreamError>;

    /// Publishes `bytes` as `name` on the shelf `shelf`, once: the same bytes again are the
    /// first, other bytes are refused with [`StreamError::Corruption`] and the first stays.
    fn publish(&self, shelf: &str, name: &str, bytes: &[u8]) -> Result<(), StreamError>;

    /// Removes `names` from the shelf `shelf`, durably.
    fn unlink(&self, shelf: &str, names: &[String]) -> Result<(), StreamError>;
}

/// The runs of one consumer: the only way it reaches one. `component` is a resource's
/// component, `producer` and `run` hex.
pub trait Runs: Send + Sync {
    /// Whether a run opened stays valid in the process between holds: true where the process
    /// is the only writer, so the consumer keeps it open; false where any instance may write,
    /// so the consumer opens it for each hold and reads it again.
    fn kept_open(&self) -> bool;

    /// The run `run` of `producer` under `component`, opened for one holder; created when
    /// `create`, `None` when absent otherwise.
    fn open(
        &self,
        component: &str,
        producer: &str,
        run: &str,
        create: bool,
    ) -> Result<Option<Box<dyn RunStore>>, StreamError>;

    /// The run `run` of `producer` under `component`, to read what it holds besides its
    /// journal; `None` when absent. It opens no journal and takes no hold.
    fn peek(
        &self,
        component: &str,
        producer: &str,
        run: &str,
    ) -> Result<Option<Box<dyn RunFiles>>, StreamError>;

    /// The view `name` of `producer` under `component`.
    fn producer_view(
        &self,
        component: &str,
        producer: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>, StreamError>;

    /// Replaces the view `name` of `producer` under `component`.
    fn replace_producer_view(
        &self,
        component: &str,
        producer: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StreamError>;

    /// The view `name` of `component`.
    fn resource_view(&self, component: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError>;

    /// Replaces the view `name` of `component`.
    fn replace_resource_view(
        &self,
        component: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StreamError>;

    /// The components runs are held under.
    fn components(&self) -> Result<Vec<String>, StreamError>;

    /// The producers runs are held of under `component`.
    fn producers(&self, component: &str) -> Result<Vec<String>, StreamError>;

    /// The runs held of `producer` under `component`.
    fn runs(&self, component: &str, producer: &str) -> Result<Vec<String>, StreamError>;

    /// Lets go of the room kept for a deletion's writes beside `producer`'s runs, before the
    /// deletion writes; nothing where none is kept.
    fn release_reserve(&self, component: &str, producer: &str) -> Result<(), StreamError>;

    /// Keeps that room again, after the deletion; nothing where none is kept.
    fn keep_reserve(&self, component: &str, producer: &str);
}

/// The file a producer's reserve is kept in.
pub(crate) const RESERVE_FILE: &str = "RESERVE";
/// How much room the reserve keeps.
pub(crate) const RESERVE_BYTES: u64 = 64 * 1024;
/// The directory a run's journal is kept in.
const RECORDS_DIR: &str = "records";

/// The runs of a consumer below its directory on a volume.
#[derive(Debug)]
pub struct FileRuns {
    dir: Dir,
    claim: u64,
    segment_bytes: u64,
}

/// The subdirectory `name` of `dir`, created when `create`, `None` when absent otherwise.
pub(crate) fn child(dir: &Dir, name: &str, create: bool) -> Result<Option<Dir>, StreamError> {
    if create || dir.subdirs()?.iter().any(|held| held == name) {
        return Ok(Some(dir.subdir(name, true)?));
    }
    Ok(None)
}

impl FileRuns {
    /// The runs below `dir`, their journals written under the volume claim `claim` and rolling
    /// their segments past `segment_bytes`.
    pub fn new(dir: Dir, claim: u64, segment_bytes: u64) -> Self {
        Self {
            dir,
            claim,
            segment_bytes,
        }
    }

    fn producer(
        &self,
        component: &str,
        producer: &str,
        create: bool,
    ) -> Result<Option<Dir>, StreamError> {
        let Some(resource) = child(&self.dir, component, create)? else {
            return Ok(None);
        };
        child(&resource, producer, create)
    }
}

impl Runs for FileRuns {
    fn kept_open(&self) -> bool {
        true
    }

    fn open(
        &self,
        component: &str,
        producer: &str,
        run: &str,
        create: bool,
    ) -> Result<Option<Box<dyn RunStore>>, StreamError> {
        let Some(producer) = self.producer(component, producer, create)? else {
            return Ok(None);
        };
        if create && !producer.exists(RESERVE_FILE)? {
            // The reserve a deletion's writes take (WP-5.6b); where the filesystem cannot
            // allocate it, the consumer goes on without.
            let _ =
                permguard_host::storage::write::allocate(&producer, RESERVE_FILE, RESERVE_BYTES);
        }
        let Some(dir) = child(&producer, run, create)? else {
            return Ok(None);
        };
        let (journal, _) = Journal::open(
            dir.subdir(RECORDS_DIR, true)?,
            Options {
                claim: self.claim,
                segment_bytes: self.segment_bytes,
                ..Options::default()
            },
        )?;
        Ok(Some(Box::new(FileRun { dir, journal })))
    }

    fn peek(
        &self,
        component: &str,
        producer: &str,
        run: &str,
    ) -> Result<Option<Box<dyn RunFiles>>, StreamError> {
        let Some(producer) = self.producer(component, producer, false)? else {
            return Ok(None);
        };
        Ok(child(&producer, run, false)?.map(|dir| Box::new(dir) as Box<dyn RunFiles>))
    }

    fn producer_view(
        &self,
        component: &str,
        producer: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>, StreamError> {
        match self.producer(component, producer, false)? {
            Some(dir) => Ok(read_view(&dir, name, format::VIEW)?),
            None => Ok(None),
        }
    }

    fn replace_producer_view(
        &self,
        component: &str,
        producer: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StreamError> {
        let dir = self
            .producer(component, producer, true)?
            .ok_or_else(|| StreamError::Corruption("a producer directory is absent".to_owned()))?;
        Ok(replace_view(&dir, name, format::VIEW, bytes)?)
    }

    fn resource_view(&self, component: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        match child(&self.dir, component, false)? {
            Some(dir) => Ok(read_view(&dir, name, format::VIEW)?),
            None => Ok(None),
        }
    }

    fn replace_resource_view(
        &self,
        component: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StreamError> {
        let dir = child(&self.dir, component, true)?
            .ok_or_else(|| StreamError::Corruption("a resource directory is absent".to_owned()))?;
        Ok(replace_view(&dir, name, format::VIEW, bytes)?)
    }

    fn components(&self) -> Result<Vec<String>, StreamError> {
        Ok(self.dir.subdirs()?)
    }

    fn producers(&self, component: &str) -> Result<Vec<String>, StreamError> {
        match child(&self.dir, component, false)? {
            Some(dir) => Ok(dir.subdirs()?),
            None => Ok(Vec::new()),
        }
    }

    fn runs(&self, component: &str, producer: &str) -> Result<Vec<String>, StreamError> {
        match self.producer(component, producer, false)? {
            Some(dir) => Ok(dir.subdirs()?),
            None => Ok(Vec::new()),
        }
    }

    fn release_reserve(&self, component: &str, producer: &str) -> Result<(), StreamError> {
        if let Some(dir) = self.producer(component, producer, false)? {
            permguard_host::storage::write::release(&dir, RESERVE_FILE)?;
        }
        Ok(())
    }

    fn keep_reserve(&self, component: &str, producer: &str) {
        if let Ok(Some(dir)) = self.producer(component, producer, false) {
            let _ = permguard_host::storage::write::allocate(&dir, RESERVE_FILE, RESERVE_BYTES);
        }
    }
}

fn view_of(dir: &Dir, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
    Ok(read_view(dir, name, format::VIEW)?)
}

fn read_of(dir: &Dir, shelf: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
    match child(dir, shelf, false)? {
        Some(dir) => Ok(dir.read(name)?),
        None => Ok(None),
    }
}

fn names_of(dir: &Dir, shelf: &str) -> Result<Vec<String>, StreamError> {
    match child(dir, shelf, false)? {
        // A file a crash left half-published is no file of the shelf.
        Some(dir) => Ok(dir
            .names()?
            .into_iter()
            .filter(|name| !name.starts_with(permguard_host::storage::dir::TEMP_PREFIX))
            .collect()),
        None => Ok(Vec::new()),
    }
}

/// A run's directory, read without its journal: the file backend's [`RunFiles`].
impl RunFiles for Dir {
    fn view(&self, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        view_of(self, name)
    }

    fn read(&self, shelf: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        read_of(self, shelf, name)
    }

    fn names(&self, shelf: &str) -> Result<Vec<String>, StreamError> {
        names_of(self, shelf)
    }
}

/// One run's directory and its journal.
struct FileRun {
    dir: Dir,
    journal: Journal,
}

impl RunFiles for FileRun {
    fn view(&self, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        view_of(&self.dir, name)
    }

    fn read(&self, shelf: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        read_of(&self.dir, shelf, name)
    }

    fn names(&self, shelf: &str) -> Result<Vec<String>, StreamError> {
        names_of(&self.dir, shelf)
    }
}

impl RunStore for FileRun {
    fn frames(&self) -> Result<Vec<Frame>, StreamError> {
        Ok(self.journal.frames()?)
    }

    fn frames_from(&self, index: u64) -> Result<Vec<Frame>, StreamError> {
        Ok(self.journal.frames_from(index)?)
    }

    fn first_index(&self) -> u64 {
        self.journal.first_index()
    }

    fn next_index(&self) -> u64 {
        self.journal.next_index()
    }

    fn segment_starts(&self) -> Vec<u64> {
        self.journal.segment_starts()
    }

    fn append(&mut self, kind: u16, payload: &[u8]) -> Result<u64, StreamError> {
        Ok(self.journal.append(kind, payload)?)
    }

    fn drop_prefix(&mut self, below: u64) -> Result<u64, StreamError> {
        Ok(self.journal.drop_prefix(below, None)?)
    }

    fn replace_view(&self, name: &str, bytes: &[u8]) -> Result<(), StreamError> {
        Ok(replace_view(&self.dir, name, format::VIEW, bytes)?)
    }

    fn publish(&self, shelf: &str, name: &str, bytes: &[u8]) -> Result<(), StreamError> {
        let shelf = self.dir.subdir(shelf, true)?;
        match publish_immutable(&shelf, name, bytes, &|_| true, &|stored| stored == bytes) {
            Ok(Published::Written | Published::AlreadyThere) => Ok(()),
            Err(StorageError::Corruption(detail)) => Err(StreamError::Corruption(detail)),
            Err(error) => Err(error.into()),
        }
    }

    fn unlink(&self, shelf: &str, names: &[String]) -> Result<(), StreamError> {
        let Some(dir) = child(&self.dir, shelf, false)? else {
            return Ok(());
        };
        for name in names {
            dir.unlink(name)?;
        }
        dir.sync()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// The file backend passes the contract's suite, each case below a directory of its own.
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let root = std::env::temp_dir().join(format!(
            "permguard-stream-runs-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let made = AtomicUsize::new(0);
        super::super::suite::run(&|| {
            let case = root.join(format!("case-{}", made.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(&case).expect("a directory");
            Arc::new(FileRuns::new(
                Dir::open(&case).expect("opened"),
                0,
                permguard_host::storage::journal::DEFAULT_SEGMENT_BYTES,
            ))
        });
        let _ = std::fs::remove_dir_all(root);
    }
}
