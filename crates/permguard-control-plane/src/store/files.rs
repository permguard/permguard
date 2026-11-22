// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`LedgerStore`] and [`Ledgers`]: one ledger directory on the local
//! filesystem, below the zones root.
//!
//! ```text
//! <zones>/<zone>/ledgers/<ledger>/
//! ├── FORMAT              the layout every other file is read under
//! ├── objects/ab/cdef…    one file per object, digest-fanout, immutable
//! ├── refs/<name>         JSON: the head digest, the monotonic counter, the previous state's
//! │                       `ref_digest` and the operation that wrote it
//! ├── roots/<digest>      a head kept as a root of the collection, one empty file each
//! ├── signatures/…        COSE_Sign1 head statements, a replaceable cache
//! └── transfers/<id>.cbor one closed CBOR record per transfer session
//! ```
//!
//! Objects are zlib-compressed at rest — the shelf git keeps loose objects
//! on — and their digests name the uncompressed canonical bytes. A `FORMAT`
//! file at the ledger root pins the layout: a store written by a different
//! layout is refused, never guessed at.
//!
//! Objects are verified canonical before they land, and published through the
//! storage library without replacement (H-06): writing the same object twice
//! is a no-op that rewrites nothing, and a name holding a different object is
//! corruption, left as it was.
//! Ref updates satisfy the abstract property of the specification —
//! linearizable, `(head, counter)` one atomic durable unit — with a
//! process-wide mutex per store and the write sequence: write temp, fsync
//! temp, atomic rename, fsync the containing directory. Reads never lock.
//!
//! One maintaining process per volume, like the catalog: a deployment that
//! wants replicas arbitrates behind a store that can.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::Applying;
use permguard_host::storage::write::{Published, publish_immutable};
use permguard_host::storage::{Dir, StorageError};
use permguard_notp::ExpectedRef;
use permguard_objects::compress;
use permguard_objects::digest::Digest;
use permguard_objects::grammar;
use permguard_objects::limits;
use permguard_objects::object::{self, Object, ObjectError};

use super::{
    FORMAT, Landed, LedgerStore, Ledgers, RefState, RefUpdate, Result, StoreError, StoredObject,
    TransferSessions, backend, ref_digest,
};
use crate::transfer::Transfers;

/// The directory of a ledger's transfer sessions.
pub const TRANSFERS: &str = "transfers";

/// The directory of a ledger's kept roots (BUG-0185): one empty file per head, named for it.
const ROOTS: &str = "roots";

/// The file name a root is kept under: its digest, the colon a file name cannot carry everywhere
/// replaced.
fn root_name(head: &Digest) -> String {
    head.to_string().replacen(':', "-", 1)
}

/// The object store of one ledger directory.
pub struct FileObjectStore {
    root: PathBuf,
    /// Serialises ref mutations; object writes are idempotent and need none.
    refs_lock: Mutex<()>,
    /// Serialises the transitions of the transfer sessions (WP-7.12).
    transfers_lock: Mutex<()>,
    /// The `FORMAT` gate, set once it passed.
    format: OnceLock<()>,
}

impl FileObjectStore {
    /// Opens the store over a ledger directory, creating nothing until
    /// something is stored.
    pub fn new(ledger_directory: impl Into<PathBuf>) -> Self {
        Self {
            root: ledger_directory.into(),
            refs_lock: Mutex::new(()),
            transfers_lock: Mutex::new(()),
            format: OnceLock::new(),
        }
    }

    /// The `FORMAT` gate: a fresh directory gets the pin written; a pinned
    /// directory must match; a populated directory without a pin was written
    /// by an older layout — refused with what to do about it.
    fn check_format(&self) -> Result<()> {
        if self.format.get().is_some() {
            return Ok(());
        }
        let checked = (|| {
            let path = self.root.join("FORMAT");
            match fs::read_to_string(&path) {
                Ok(found) => {
                    let found = found.trim();
                    if found == FORMAT {
                        Ok(())
                    } else {
                        Err(StoreError::Incompatible {
                            found: found.to_owned(),
                        })
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if self.root.join("objects").exists() || self.root.join("refs").exists() {
                        // A first push through another store over this directory may have
                        // pinned the format since the read above: the pin is always written
                        // before anything else, so it is read once more before calling the
                        // directory unversioned.
                        return match fs::read_to_string(&path) {
                            Ok(found) if found.trim() == FORMAT => Ok(()),
                            Ok(found) => Err(StoreError::Incompatible {
                                found: found.trim().to_owned(),
                            }),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                Err(StoreError::Incompatible {
                                    found: "unversioned".to_owned(),
                                })
                            }
                            Err(error) => Err(backend("reading FORMAT", error)),
                        };
                    }
                    write_durable(&self.root, "FORMAT", format!("{FORMAT}\n").as_bytes())
                }
                Err(error) => Err(backend("reading FORMAT", error)),
            }
        })();
        // Only a gate that passed is remembered: a ledger repaired is served by the next call.
        if checked.is_ok() {
            let _ = self.format.set(());
        }
        checked
    }

    /// The ledger directory this store lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, digest: &Digest) -> PathBuf {
        let (shard, name) = Self::object_location(digest);
        self.root.join("objects").join(shard).join(name)
    }

    /// The shard directory and the file name of an object: the first two hex characters of its
    /// digest, and the rest.
    fn object_location(digest: &Digest) -> (String, String) {
        let hex = digest.to_string();
        let hex = &hex["sha256:".len()..];
        (hex[..2].to_owned(), hex[2..].to_owned())
    }

    fn ref_path(&self, name: &str) -> PathBuf {
        self.root.join("refs").join(name)
    }

    fn signature_path(&self, name: &str) -> PathBuf {
        // Refs may contain `/`; the signature file mirrors the ref path.
        self.root.join("signatures").join(name)
    }
}

impl LedgerStore for FileObjectStore {
    /// A file stat, nothing more.
    fn has_object(&self, digest: &Digest) -> bool {
        self.object_path(digest).exists()
    }

    /// Keeps `heads` as roots of the collection (BUG-0185): the history a re-home imported, which
    /// no ref of the new ledger names, and none may ever name; what a root reaches is never swept
    /// while the ledger exists. Kept once, a root is never removed.
    fn keep_roots(&self, heads: &[Digest]) -> Result<()> {
        self.check_format()?;
        let directory = Dir::open(&self.root)
            .and_then(|root| root.subdir(ROOTS, true))
            .map_err(|error| storage("opening the roots", error))?;
        for head in heads {
            publish_immutable(&directory, &root_name(head), b"", &|_| true, &|held| {
                held.is_empty()
            })
            .map_err(|error| storage("keeping a root", error))?;
        }
        Ok(())
    }

    /// The roots [`Self::keep_roots`] keeps, sorted.
    fn roots(&self) -> Result<Vec<Digest>> {
        if !self.root.join(ROOTS).is_dir() {
            return Ok(Vec::new());
        }
        let directory = Dir::open(&self.root)
            .and_then(|root| root.subdir(ROOTS, false))
            .map_err(|error| storage("opening the roots", error))?;
        let mut roots = Vec::new();
        for name in directory
            .names()
            .map_err(|error| storage("listing the roots", error))?
        {
            let Some(digest) = name
                .strip_prefix("sha256-")
                .and_then(|hex| Digest::parse(&format!("sha256:{hex}")).ok())
            else {
                continue;
            };
            roots.push(digest);
        }
        roots.sort();
        Ok(roots)
    }

    /// Published through the storage library's no-replace path (H-06): a
    /// flushed temporary is hard-linked to the object's name, which fails when
    /// the name exists. Two pushes of one object at once end with one write and
    /// one no-op; a name already holding *different* content — whose bytes no
    /// longer decompress to this object — is [`StoreError::Corrupt`], and the
    /// existing file is left byte-for-byte as it was.
    fn publish_object(&self, bytes: &[u8]) -> Result<(Digest, Object, Landed)> {
        if bytes.len() > limits::MAX_OBJECT_BYTES {
            return Err(ObjectError::Limit("object bytes").into());
        }
        self.check_format()?;
        let decoded = object::decode(bytes)?;
        let digest = Digest::compute(bytes);
        let (shard, name) = Self::object_location(&digest);
        // The ledger directory exists once the format is pinned; below it, nothing is followed.
        let directory = Dir::open(&self.root)
            .and_then(|root| root.subdir("objects", true))
            .and_then(|objects| objects.subdir(&shard, true))
            .map_err(|error| storage("opening the object directory", error))?;
        // Compared as content, not as compressed bytes: two compressors may encode one object
        // differently, and only the object is the identity.
        let holds_this = |stored: &[u8]| {
            compress::inflate(stored, limits::MAX_OBJECT_BYTES).is_ok_and(|held| held == bytes)
        };
        let published = publish_immutable(
            &directory,
            &name,
            &compress::deflate(bytes),
            &holds_this,
            &holds_this,
        )
        .map_err(|error| match error {
            StorageError::Corruption(_) => StoreError::Corrupt {
                digest: digest.clone(),
            },
            other => storage("publishing object", other),
        })?;
        let landed = match published {
            Published::Written => Landed::Written,
            Published::AlreadyThere => Landed::AlreadyThere,
        };
        Ok((digest, decoded, landed))
    }

    /// Read one object, verifying on the way out that the bytes still hash
    /// to their name — corruption is detected here, never served silently.
    fn get_object(&self, digest: &Digest) -> Result<Option<Vec<u8>>> {
        self.check_format()?;
        let path = self.object_path(digest);
        let stored = match fs::read(&path) {
            Ok(stored) => stored,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(backend("reading object", error)),
        };
        let bytes = compress::inflate(&stored, limits::MAX_OBJECT_BYTES).map_err(|_| {
            StoreError::Corrupt {
                digest: digest.clone(),
            }
        })?;
        if Digest::compute(&bytes) != *digest {
            return Err(StoreError::Corrupt {
                digest: digest.clone(),
            });
        }
        Ok(Some(bytes))
    }

    /// Read a ref's `(head, counter)` — lockless: the file is replaced
    /// atomically, so any read is a consistent snapshot.
    fn read_ref(&self, name: &str) -> Result<Option<RefState>> {
        grammar::validate_ref_name(name)?;
        let path = self.ref_path(name);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(backend("reading ref", error)),
        };
        parse_ref(&text)
            .ok_or_else(|| StoreError::Backend {
                detail: format!("{} is not a ref record", path.display()),
            })
            .map(Some)
    }

    /// The WP-3.6 operation that wrote the ref `name`, when its record names one.
    fn ref_operation(&self, name: &str) -> Result<Option<String>> {
        grammar::validate_ref_name(name)?;
        match fs::read_to_string(self.ref_path(name)) {
            Ok(text) => Ok(parse_operation(&text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(backend("reading ref", error)),
        }
    }

    /// Every object in the store: its digest, how old the file is, and how
    /// many bytes it occupies.
    ///
    /// A directory walk and one `stat` per file — nothing is read and nothing
    /// is decompressed, because the sweep that uses this decides by
    /// reachability and age, never by content. A name that is not a digest is
    /// skipped rather than guessed at: a stray file in the fanout is somebody
    /// else's, and this is not the place to have an opinion about it.
    fn list_objects(&self) -> Result<Vec<StoredObject>> {
        let base = self.root.join("objects");
        let mut held = Vec::new();
        let fans = match fs::read_dir(&base) {
            Ok(fans) => fans,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(held),
            Err(error) => return Err(backend("listing objects", error)),
        };
        for fan in fans {
            let fan = fan.map_err(|error| backend("listing objects", error))?;
            let prefix = fan.file_name().to_string_lossy().into_owned();
            if prefix.len() != 2 || !fan.path().is_dir() {
                continue;
            }
            let entries = match fs::read_dir(fan.path()) {
                Ok(entries) => entries,
                Err(error) => return Err(backend("listing objects", error)),
            };
            for entry in entries {
                let entry = entry.map_err(|error| backend("listing objects", error))?;
                let rest = entry.file_name().to_string_lossy().into_owned();
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                if !metadata.is_file() {
                    continue;
                }
                let Ok(digest) = Digest::parse(&format!("sha256:{prefix}{rest}")) else {
                    continue;
                };
                held.push(StoredObject {
                    digest,
                    bytes: metadata.len(),
                    // A clock that cannot answer is treated as "just written",
                    // which keeps the object: the safe direction.
                    modified: metadata
                        .modified()
                        .unwrap_or_else(|_| std::time::SystemTime::now()),
                });
            }
        }
        held.sort_by_key(|object| object.digest.to_string());

        Ok(held)
    }

    /// Removes one object. Answers the bytes reclaimed, `0` when it was
    /// already gone.
    ///
    /// The path is **built from the digest**, never taken from a caller, so
    /// there is no path for this to reach outside the store's own fanout. It
    /// refuses anything that is not a plain file, and removing what is not
    /// there is a success: two sweeps racing must not turn into an error.
    fn remove_object(&self, digest: &Digest) -> Result<u64> {
        let path = self.object_path(digest);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(backend("reading an object", error)),
        };
        if !metadata.is_file() {
            return Err(StoreError::Backend {
                detail: format!("{} is not a file: refusing to remove it", path.display()),
            });
        }
        match fs::remove_file(&path) {
            Ok(()) => Ok(metadata.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(backend("removing an object", error)),
        }
    }

    /// Flushes the ref `name` and its directory, so that an answer saying the ref is where it is
    /// never rests on a rename another update has not flushed yet.
    fn make_ref_durable(&self, name: &str) -> Result<()> {
        grammar::validate_ref_name(name)?;
        let parts: Vec<&str> = name.split('/').collect();
        let Some((file, parents)) = parts.split_last() else {
            return Ok(());
        };
        let flushing = |error| storage("flushing a ref", error);
        let mut dir = Dir::open(&self.root)
            .and_then(|root| root.subdir("refs", false))
            .map_err(flushing)?;
        for parent in parents {
            dir = dir.subdir(parent, false).map_err(flushing)?;
        }
        dir.sync_file(file).map_err(flushing)?;
        dir.sync().map_err(flushing)
    }

    /// Flushes the directory entries of the objects `digests` name, so that a ref about to reach
    /// them never outlives them.
    ///
    /// An object's bytes were flushed by whoever published it, before it was linked; its entry
    /// becomes durable with its shard directory, which this flushes once per shard, and with the
    /// shard's own entry, which `subdir` makes durable.
    fn make_durable(&self, digests: &std::collections::BTreeSet<Digest>) -> Result<()> {
        if digests.is_empty() {
            return Ok(());
        }
        let shards: std::collections::BTreeSet<String> = digests
            .iter()
            .map(|digest| Self::object_location(digest).0)
            .collect();
        let objects = Dir::open(&self.root)
            .and_then(|root| root.subdir("objects", true))
            .map_err(|error| storage("opening the object directory", error))?;
        // `create` only for what it brings: the shard's own entry made durable in `objects`. The
        // shards exist, since every object of the region was just read from them.
        for shard in shards {
            objects
                .subdir(&shard, true)
                .and_then(|directory| directory.sync())
                .map_err(|error| storage("flushing an object directory", error))?;
        }
        Ok(())
    }

    /// Removes the temporary files that writes interrupted by a crash left anywhere in this
    /// ledger, once they are older than `older_than`; answers how many.
    ///
    /// A temporary is never the authority for anything, but one may belong to a write still in
    /// flight through another handle on this ledger, so only one older than any write lasts is
    /// removed: the collector passes its grace period, which already has to outlast a push.
    fn sweep_temporaries(&self, older_than: std::time::Duration) -> Result<usize> {
        let root = match Dir::open(&self.root) {
            Ok(root) => root,
            Err(StorageError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(0);
            }
            Err(error) => return Err(storage("opening the ledger", error)),
        };
        sweep_tree(&root, older_than)
    }

    /// What Load verifies of this ledger before the plane serves it (BUG-0255), reading only and
    /// writing nothing: its `FORMAT` pin is this build's, or the directory holds nothing yet, and
    /// every ref parses and names a head the store holds. Answers how many refs it checked.
    fn verify_at_load(&self) -> Result<usize> {
        match fs::read_to_string(self.root.join("FORMAT")) {
            Ok(found) if found.trim() == FORMAT => {}
            Ok(found) => {
                return Err(StoreError::Incompatible {
                    found: found.trim().to_owned(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self.root.join("objects").exists() || self.root.join("refs").exists() {
                    return Err(StoreError::Incompatible {
                        found: "unversioned".to_owned(),
                    });
                }
                return Ok(0);
            }
            Err(error) => return Err(backend("reading FORMAT", error)),
        }
        // Every ref file, read strictly: a listing skips one it cannot parse, and Load must not.
        let mut names = Vec::new();
        ref_names(&self.root.join("refs"), &self.root.join("refs"), &mut names)?;
        for name in &names {
            let state = self.read_ref(name)?.ok_or_else(|| StoreError::Backend {
                detail: format!("the ref {name} vanished while it was read"),
            })?;
            if !self.has_object(&state.head) {
                return Err(StoreError::Backend {
                    detail: format!(
                        "the ref {name} names the head {} the store does not hold",
                        state.head
                    ),
                });
            }
        }
        Ok(names.len())
    }

    /// List every ref, by walking `refs/`.
    fn list_refs(&self) -> Result<Vec<(String, RefState)>> {
        let mut out = Vec::new();
        let base = self.root.join("refs");
        collect_refs(&base, &base, &mut out)?;
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// The idempotent compare-and-swap of the specification, over the ref state the caller
    /// expects, `(counter, ref_digest)`:
    ///
    /// | current state                         | result                                  |
    /// | ------------------------------------- | --------------------------------------- |
    /// | head `== new`                         | `AlreadyCurrent`, counter untouched     |
    /// | `(counter, ref_digest) == expected`   | the successor state, written atomically |
    /// | anything else                         | `Conflict`, carrying what is current    |
    ///
    /// `expected = None` is the creation case: it succeeds only while the
    /// ref does not exist, and the counter starts at 1.
    ///
    /// A ref update is a security mutation (WP-3.6): it runs inside the Host's transaction, whose
    /// token it takes, and the record it writes carries the operation id, so recovery tells an
    /// update that landed from one that did not.
    fn update_ref(
        &self,
        applying: &Applying<'_>,
        name: &str,
        expected: Option<&ExpectedRef>,
        new: &Digest,
    ) -> Result<RefUpdate> {
        grammar::validate_ref_name(name)?;
        self.check_format()?;
        let _guard = self.refs_lock.lock().map_err(|_| StoreError::Backend {
            detail: "the ref lock is poisoned".into(),
        })?;

        let current = self.read_ref(name)?;

        if let Some(state) = &current
            && state.head == *new
        {
            // A success is a durable claim: the ref may be one a concurrent update renamed into
            // place and has not flushed yet.
            self.make_ref_durable(name)?;
            return Ok(RefUpdate::AlreadyCurrent(state.clone()));
        }

        let state = match (expected, &current) {
            (None, None) => RefState::first(new.clone()),
            (Some(expected), Some(state))
                if expected.counter == state.counter && expected.digest == ref_digest(state)? =>
            {
                state
                    .successor(new.clone())
                    .map_err(|error| backend("the next ref state", error))?
            }
            _ => return Err(StoreError::Conflict { current }),
        };
        write_durable(
            &self.root,
            &format!("refs/{name}"),
            render_ref(&state, Some(&applying.operation_id())).as_bytes(),
        )?;
        Ok(RefUpdate::Updated(state))
    }

    fn transfers(&self) -> Result<Transfers<'_>> {
        self.check_format()?;
        let guard = self
            .transfers_lock
            .lock()
            .map_err(|_| StoreError::Backend {
                detail: "the transfer lock is poisoned".into(),
            })?;
        Ok(Transfers::new(
            self,
            Box::new(FileSessions {
                root: &self.root,
                _guard: guard,
            }),
        ))
    }

    /// Every file below `objects/`, a write in flight included.
    fn stored_bytes(&self) -> Result<u64> {
        fn sum(directory: &Path) -> std::io::Result<u64> {
            let mut total = 0;
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                if meta.is_dir() {
                    total += sum(&entry.path())?;
                } else {
                    total += meta.len();
                }
            }
            Ok(total)
        }
        let objects = self.root.join("objects");
        if !objects.exists() {
            return Ok(0);
        }
        sum(&objects).map_err(|error| backend("sizing the ledger", error))
    }

    /// Store the signed head statement for a ref — a cache, replaced on
    /// every update, verified against the current ref before being served.
    fn write_signature(&self, name: &str, envelope: &[u8]) -> Result<()> {
        grammar::validate_ref_name(name)?;
        write_durable(&self.root, &format!("signatures/{name}"), envelope)
    }

    /// Read the cached statement envelope for a ref, if any.
    fn read_signature(&self, name: &str) -> Result<Option<Vec<u8>>> {
        grammar::validate_ref_name(name)?;
        match fs::read(self.signature_path(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(backend("reading signature", error)),
        }
    }
}

/// A ledger's transfer sessions on files, `transfers/<id>.cbor`, held under its store's transfer
/// lock.
struct FileSessions<'a> {
    root: &'a Path,
    _guard: MutexGuard<'a, ()>,
}

impl FileSessions<'_> {
    fn name(transfer_id: &[u8; 16]) -> String {
        format!("{}.cbor", permguard_core::encoding::hex(transfer_id))
    }
}

impl TransferSessions for FileSessions<'_> {
    fn get(&self, transfer_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        match fs::read(self.root.join(TRANSFERS).join(Self::name(transfer_id))) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(backend("reading a session", error)),
        }
    }

    fn list(&self) -> Result<Vec<Vec<u8>>> {
        let entries = match fs::read_dir(self.root.join(TRANSFERS)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(backend("listing sessions", error)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| backend("listing sessions", error))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // The storage library's temporaries are swept with the ledger's.
            if name.ends_with(".cbor") {
                names.push(name);
            }
        }
        // A session's file is named for its id in hex, so the names sort as the ids do.
        names.sort();
        names
            .iter()
            .map(|name| {
                fs::read(self.root.join(TRANSFERS).join(name))
                    .map_err(|error| backend("reading a session", error))
            })
            .collect()
    }

    fn put(&self, transfer_id: &[u8; 16], record: &[u8]) -> Result<()> {
        write_durable(
            self.root,
            &format!("{TRANSFERS}/{}", Self::name(transfer_id)),
            record,
        )
    }

    fn remove(&self, transfer_id: &[u8; 16]) -> Result<()> {
        let dir = Dir::create_root(self.root)
            .and_then(|root| root.subdir(TRANSFERS, true))
            .map_err(|error| storage("opening the sessions", error))?;
        dir.unlink(&Self::name(transfer_id))
            .map_err(|error| storage("removing a session", error))?;
        Ok(())
    }
}

/// The ledgers below a zones root, `<zones>/<zone>/ledgers/<ledger>/`, one store each for the
/// life of the process: the locks of a ledger's refs and of its transfer sessions are its
/// store's, so every reader and writer of a ledger has to meet in the same one.
pub struct FileLedgers {
    zones_root: PathBuf,
    stores: Mutex<HashMap<(String, String), Arc<FileObjectStore>>>,
}

impl FileLedgers {
    /// The ledgers below `zones_root`; nothing is opened or created until a ledger is used.
    pub fn new(zones_root: impl Into<PathBuf>) -> Self {
        Self {
            zones_root: zones_root.into(),
            stores: Mutex::new(HashMap::new()),
        }
    }

    /// The zones root the ledgers live below.
    pub fn zones_root(&self) -> &Path {
        &self.zones_root
    }

    /// The file store of one ledger: [`Ledgers::ledger`], for what needs its directory.
    pub fn file(&self, zone: &str, ledger: &str) -> Arc<FileObjectStore> {
        // The map is whole whatever a holder of its lock was doing when it panicked.
        let mut stores = self
            .stores
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            stores
                .entry((zone.to_owned(), ledger.to_owned()))
                .or_insert_with(|| {
                    Arc::new(FileObjectStore::new(
                        self.zones_root.join(zone).join("ledgers").join(ledger),
                    ))
                }),
        )
    }
}

impl Ledgers for FileLedgers {
    fn ledger(&self, zone: &str, ledger: &str) -> Arc<dyn LedgerStore> {
        self.file(zone, ledger)
    }
}

/// Which of this store's files are the authority and which can be rebuilt (P4).
impl permguard_host::storage::authority::Declared for FileObjectStore {
    fn files() -> &'static [permguard_host::storage::authority::FileClass] {
        use permguard_host::storage::authority::{Authority, FileClass};

        &[
            FileClass {
                pattern: "objects/<2 hex>/<62 hex>",
                authority: Authority::Authoritative,
                why: "the ledger's content, named by its digest",
            },
            FileClass {
                pattern: "refs/<name>",
                authority: Authority::Authoritative,
                why: "each ref's head, monotonic counter and previous state's digest",
            },
            FileClass {
                pattern: "FORMAT",
                authority: Authority::Authoritative,
                why: "the layout every other file is read under",
            },
            FileClass {
                pattern: "signatures/<ref>",
                authority: Authority::Rebuildable,
                why: "a cache of the head statements, signed again whenever it is missing or stale",
            },
            FileClass {
                pattern: "transfers/<32 hex>.cbor",
                authority: Authority::Authoritative,
                why: "a transfer session: its binding, reservation, pins and answer (WP-7.12)",
            },
        ]
    }
}

/// A storage-library failure, as this store reports it.
fn storage(what: &str, error: StorageError) -> StoreError {
    StoreError::Backend {
        detail: format!("{what}: {error}"),
    }
}

/// Replaces the file `relative` (`/`-separated) below the ledger directory `root` with `bytes`: a
/// fresh, exclusively created temporary, flushed, renamed over the target, and the directory
/// flushed. Below `root` every directory is opened relative to its parent without following a
/// link, and every directory created is flushed into its parent. The temporary's name is random,
/// so two writers of one file never share a temporary; a failed flush is reported, never ignored.
pub(crate) fn write_durable(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    let parts: Vec<&str> = relative.split('/').collect();
    let Some((name, parents)) = parts.split_last() else {
        return Err(StoreError::Backend {
            detail: format!("`{relative}` names no file"),
        });
    };
    let mut dir = Dir::create_root(root).map_err(|error| storage("opening directory", error))?;
    for parent in parents {
        dir = dir
            .subdir(parent, true)
            .map_err(|error| storage("opening directory", error))?;
    }
    permguard_host::storage::write::replace_bytes(&dir, name, bytes)
        .map_err(|error| storage("atomic replace", error))
}

/// Removes the temporaries below `dir`, in it and in every subdirectory, older than `older_than`:
/// the storage library's, and the `*.tmp` files of the layout before it. Every directory is listed
/// and opened through its parent's handle, never by following a link; one that disappears while
/// the sweep walks is skipped.
fn sweep_tree(dir: &Dir, older_than: std::time::Duration) -> Result<usize> {
    let sweeping = |error| storage("sweeping temporaries", error);
    let mut swept = dir.sweep_temps_older_than(older_than).map_err(sweeping)?;
    let now = std::time::SystemTime::now();
    for name in dir.names().map_err(sweeping)? {
        if !name.ends_with(".tmp") {
            continue;
        }
        let Some(file) = dir.open_read(&name).map_err(sweeping)? else {
            continue;
        };
        let age = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map(|modified| now.duration_since(modified).unwrap_or_default())
            .map_err(|e| backend("sweeping temporaries", e))?;
        if age >= older_than && dir.unlink(&name).map_err(sweeping)? {
            swept += 1;
        }
    }
    for name in dir.subdirs().map_err(sweeping)? {
        match dir.subdir(&name, false) {
            Ok(child) => swept += sweep_tree(&child, older_than)?,
            Err(StorageError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(sweeping(error)),
        }
    }
    Ok(swept)
}

fn render_ref(state: &RefState, operation: Option<&OperationId>) -> String {
    let previous = state
        .previous_ref_digest
        .as_ref()
        .map(|previous| format!(",\"previous\":\"{previous}\""))
        .unwrap_or_default();
    let operation = operation
        .map(|operation| format!(",\"op\":\"{operation}\""))
        .unwrap_or_default();
    format!(
        "{{\"version\":1,\"head\":\"{}\",\"counter\":{}{previous}{operation}}}\n",
        state.head, state.counter
    )
}

/// The operation id a ref record names: the WP-3.6 operation that wrote it, absent in a record
/// written before the transaction.
fn parse_operation(text: &str) -> Option<String> {
    let key = "\"op\":\"";
    let start = text.find(key)? + key.len();
    let end = text[start..].find('"')? + start;
    let id = &text[start..end];
    (id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| id.to_owned())
}

/// Parse the ref record without a JSON dependency: the format is ours, one
/// line, written only by `render_ref`; `previous` is absent at a first state and in a record
/// written before it existed.
fn parse_ref(text: &str) -> Option<RefState> {
    let quoted = |key: &str| -> Option<Option<Digest>> {
        let Some(at) = text.find(key) else {
            return Some(None);
        };
        let start = at + key.len();
        let end = text[start..].find('"')? + start;
        Digest::parse(&text[start..end]).ok().map(Some)
    };
    let head = quoted("\"head\":\"")??;
    let counter_key = "\"counter\":";
    let counter_start = text.find(counter_key)? + counter_key.len();
    let counter_end = text[counter_start..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(text.len(), |i| i + counter_start);
    let counter: u64 = text[counter_start..counter_end].parse().ok()?;
    if counter == 0 {
        return None;
    }
    let previous_ref_digest = quoted("\"previous\":\"")?;
    Some(RefState {
        head,
        counter,
        previous_ref_digest,
    })
}

/// The name of every ref file under `directory`, temporaries left out: a ref name has no `.`.
fn ref_names(base: &Path, directory: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(backend("listing refs", error)),
    };
    for entry in entries {
        let path = entry.map_err(|e| backend("listing refs", e))?.path();
        if path.is_dir() {
            ref_names(base, &path, out)?;
        } else if let Ok(relative) = path.strip_prefix(base) {
            let name = relative.to_string_lossy().replace('\\', "/");
            if !name.contains('.') {
                out.push(name);
            }
        }
    }
    out.sort();
    Ok(())
}

fn collect_refs(base: &Path, directory: &Path, out: &mut Vec<(String, RefState)>) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(backend("listing refs", error)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| backend("listing refs", e))?;
        // A temporary is never listed: a ref name has no `.`, and every temporary has one.
        let path = entry.path();
        if path.is_dir() {
            collect_refs(base, &path, out)?;
        } else if let Ok(relative) = path.strip_prefix(base) {
            let name = relative.to_string_lossy().replace('\\', "/");
            if grammar::validate_ref_name(&name).is_ok()
                && let Ok(text) = fs::read_to_string(&path)
                && let Some(state) = parse_ref(&text)
            {
                out.push((name, state));
            }
        }
    }
    Ok(())
}

/// Deep verification's check of one file below the zones directory (`storage::verify`): `Some(true)`
/// when `<zone>/<ledger>/objects/<2 hex>/<62 hex>` inflates to content whose digest is its name,
/// `Some(false)` when it does not, `None` for any other file, which is not an object.
pub fn object_check(relative: &Path, stored: &[u8]) -> Option<bool> {
    let parts: Vec<&str> = relative
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<_>>()?;
    let [_zone, _ledger, "objects", fan, rest] = parts.as_slice() else {
        return None;
    };
    if fan.len() != 2 {
        return None;
    }
    let digest = Digest::parse(&format!("sha256:{fan}{rest}")).ok()?;
    Some(
        compress::inflate(stored, limits::MAX_OBJECT_BYTES)
            .is_ok_and(|bytes| Digest::compute(&bytes) == digest),
    )
}

/// What a test or an offline tool needs to write a ref the way the server does: through an offline
/// mutation transaction of its own.
#[doc(hidden)]
pub mod testing {
    use std::path::Path;
    use std::sync::Arc;

    use permguard_host::composition::MutationHandle;
    use permguard_host::operations::journal::Initiator;
    use permguard_host::operations::mutation::{Applied, Applying, Begin, Failure, Mutations};

    use crate::store::{LedgerStore, REF_UPDATE, REFS_DOMAIN, RefUpdate, StoreError};
    use permguard_notp::ExpectedRef;
    use permguard_objects::digest::Digest;

    /// A mutation transaction of the ref updates over an offline engine on a fresh volume at
    /// `directory`.
    pub fn offline_ref_mutations(directory: &Path) -> Result<MutationHandle, String> {
        Ok(MutationHandle::new(
            offline_ref_engine(directory)?,
            REFS_DOMAIN,
        ))
    }

    /// The offline file engine [`offline_ref_mutations`] runs on, for a test that raises a
    /// backup barrier on it.
    pub fn offline_ref_engine(directory: &Path) -> Result<Arc<Mutations>, String> {
        let volume = permguard_host::storage::volume::Volume::claim(
            directory,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .map_err(|error| error.to_string())?;
        Ok(Arc::new(Mutations::open_offline(&volume, "test")?))
    }

    /// Runs `work` inside one ref-update operation of `mutations`, for a conformance suite.
    pub fn operation(mutations: &MutationHandle, work: &mut dyn FnMut(&Applying<'_>)) {
        let _ = mutations.run_checked(
            Begin {
                domain: REFS_DOMAIN,
                operation: REF_UPDATE,
                action: crate::engine::LEDGER_PUSHED,
                initiator: Initiator::System("suite".to_owned()),
                request: None,
                target: None,
            },
            || Ok::<(), StoreError>(()),
            |applying| {
                work(applying);
                Ok(Applied {
                    revision: 0,
                    target: None,
                    value: (),
                })
            },
        );
    }

    /// [`LedgerStore::update_ref`], as one operation of `mutations`.
    pub fn update_ref(
        mutations: &MutationHandle,
        store: &dyn LedgerStore,
        name: &str,
        expected: Option<&ExpectedRef>,
        new: &Digest,
    ) -> Result<RefUpdate, StoreError> {
        let answer = std::cell::RefCell::new(None);
        let _ = mutations.run_checked(
            Begin {
                domain: REFS_DOMAIN,
                operation: REF_UPDATE,
                action: crate::engine::LEDGER_PUSHED,
                initiator: Initiator::System("test".to_owned()),
                request: None,
                target: Some(name.to_owned()),
            },
            || Ok::<(), StoreError>(()),
            |applying| match store.update_ref(applying, name, expected, new) {
                Ok(update) => {
                    let revision = match &update {
                        RefUpdate::Updated(state) | RefUpdate::AlreadyCurrent(state) => {
                            state.counter
                        }
                    };
                    *answer.borrow_mut() = Some(Ok(update));
                    Ok(Applied {
                        revision,
                        target: None,
                        value: (),
                    })
                }
                Err(error) => {
                    *answer.borrow_mut() = Some(Err(error.clone()));
                    Err(Failure::Refused(error))
                }
            },
        );
        answer.into_inner().unwrap_or_else(|| {
            Err(StoreError::Backend {
                detail: "the mutation transaction ran nothing".to_owned(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_objects::object::Blob;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permguard-gitlike-store-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// One ref update through an offline mutation transaction, on a volume of its own.
    fn update(
        store: &FileObjectStore,
        name: &str,
        expected: Option<&ExpectedRef>,
        new: &Digest,
    ) -> Result<RefUpdate> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let volume = std::env::temp_dir().join(format!(
            "permguard-gitlike-volume-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&volume);
        let mutations = super::testing::offline_ref_mutations(&volume).unwrap();
        super::testing::update_ref(&mutations, store, name, expected, new)
    }

    /// The file backend passes the contract's suite, each case on a ledger directory of its own
    /// and every ref update inside an operation of an engine of its own.
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let made = std::sync::atomic::AtomicUsize::new(0);
        let root = scratch();
        crate::store::suite::run(
            &|| {
                let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Arc::new(FileObjectStore::new(root.join(format!("ledger-{case}"))))
            },
            &|work| {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let volume = std::env::temp_dir().join(format!(
                    "permguard-gitlike-suite-volume-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                ));
                let _ = fs::remove_dir_all(&volume);
                let mutations = super::testing::offline_ref_mutations(&volume).unwrap();
                super::testing::operation(&mutations, work);
                let _ = fs::remove_dir_all(&volume);
            },
        );
    }

    /// One store a ledger for the life of the ledgers: what reads and writes a ledger meets in
    /// the same holds. A session held through one handle keeps a second handle out.
    #[test]
    fn a_ledger_has_one_store_however_often_it_is_asked() {
        let ledgers = FileLedgers::new(scratch());
        let first = ledgers.file("zone-a", "ledger-1");
        assert!(Arc::ptr_eq(&first, &ledgers.file("zone-a", "ledger-1")));
        assert!(!Arc::ptr_eq(&first, &ledgers.file("zone-a", "ledger-2")));
        assert!(!Arc::ptr_eq(&first, &ledgers.file("zone-b", "ledger-1")));
        assert_eq!(
            first.root(),
            ledgers
                .zones_root()
                .join("zone-a")
                .join("ledgers")
                .join("ledger-1")
        );
        let held = ledgers.ledger("zone-a", "ledger-1");
        let _sessions = held.transfers().unwrap();
        assert!(
            first.transfers_lock.try_lock().is_err(),
            "the same ledger asked again is held by the first"
        );
    }

    /// Only a `FORMAT` gate that passed is remembered: a ledger refused for its layout is served
    /// by the same store once it is repaired, with no restart.
    #[test]
    fn a_repaired_layout_is_served_by_the_same_store() {
        let root = scratch();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("FORMAT"), "9\n").unwrap();
        let store = FileObjectStore::new(&root);
        let bytes = blob_bytes("permit (principal, action, resource);");
        assert!(matches!(
            store.put_object(&bytes),
            Err(StoreError::Incompatible { .. })
        ));
        fs::write(root.join("FORMAT"), format!("{FORMAT}\n")).unwrap();
        store.put_object(&bytes).unwrap();
    }

    fn blob_bytes(text: &str) -> Vec<u8> {
        Blob {
            media_type: "application/vnd.permguard.policy.cedar".into(),
            data: text.as_bytes().to_vec(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn objects_round_trip_and_are_idempotent() {
        let store = FileObjectStore::new(scratch());
        let bytes = blob_bytes("permit(principal, action, resource);");
        let (digest, _) = store.put_object(&bytes).unwrap();
        assert!(store.has_object(&digest));
        // Second write of the same digest: a no-op success.
        let (again, _) = store.put_object(&bytes).unwrap();
        assert_eq!(again, digest);
        assert_eq!(store.get_object(&digest).unwrap().unwrap(), bytes);
    }

    /// The storage contract (H-06), run against this store.
    #[test]
    fn the_object_store_keeps_the_immutable_storage_contract() {
        struct Objects(FileObjectStore);
        impl permguard_host::storage::testing::ImmutableStore for Objects {
            fn publish(
                &self,
                content: &[u8],
            ) -> std::result::Result<bool, permguard_host::storage::testing::Refused> {
                use permguard_host::storage::testing::Refused;
                self.0
                    .publish_object(content)
                    .map(|(_, _, published)| published == Landed::Written)
                    .map_err(|error| match error {
                        StoreError::Corrupt { .. } => Refused::Corruption(error.to_string()),
                        other => Refused::Other(other.to_string()),
                    })
            }
            fn path_of(&self, content: &[u8]) -> PathBuf {
                self.0.object_path(&Digest::compute(content))
            }
            fn read(&self, content: &[u8]) -> Option<Vec<u8>> {
                self.0.get_object(&Digest::compute(content)).ok().flatten()
            }
        }

        let store = Objects(FileObjectStore::new(scratch()));
        let content = blob_bytes("permit(principal, action, resource);");
        let forged = compress::deflate(&blob_bytes("forbid(principal, action, resource);"));
        permguard_host::storage::testing::immutable_contract(&store, &content, &forged);
    }

    /// A temporary a crash left anywhere in the ledger is removed once older than the bound, and a
    /// young one, which may be a write in flight, is kept; so is the old layout's `*.tmp`.
    #[test]
    fn temporaries_are_swept_by_age_across_the_ledger() {
        use permguard_host::storage::dir::TEMP_PREFIX;

        let store = FileObjectStore::new(scratch());
        let (digest, _) = store.put_object(&blob_bytes("kept")).unwrap();
        let head = digest.clone();
        update(&store, "feature/login", None, &head).unwrap();
        store.write_signature("feature/login", b"envelope").unwrap();
        let (shard, _) = FileObjectStore::object_location(&digest);
        let root = store.root().to_path_buf();
        let places = [
            root.join("objects").join(&shard),
            root.join("refs").join("feature"),
            root.join("signatures").join("feature"),
            root.clone(),
        ];
        let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for (at, place) in places.iter().enumerate() {
            let old = place.join(format!("{TEMP_PREFIX}00000000000000a{at}"));
            fs::write(&old, b"old").unwrap();
            fs::File::options()
                .write(true)
                .open(&old)
                .unwrap()
                .set_modified(hour_ago)
                .unwrap();
            fs::write(
                place.join(format!("{TEMP_PREFIX}00000000000000b{at}")),
                b"young",
            )
            .unwrap();
        }
        let legacy = root.join("FORMAT.tmp");
        fs::write(&legacy, b"legacy").unwrap();
        fs::File::options()
            .write(true)
            .open(&legacy)
            .unwrap()
            .set_modified(hour_ago)
            .unwrap();

        let swept = store
            .sweep_temporaries(std::time::Duration::from_secs(60))
            .unwrap();
        assert_eq!(swept, places.len() + 1);
        for (at, place) in places.iter().enumerate() {
            assert!(
                !place
                    .join(format!("{TEMP_PREFIX}00000000000000a{at}"))
                    .exists()
            );
            assert!(
                place
                    .join(format!("{TEMP_PREFIX}00000000000000b{at}"))
                    .exists()
            );
        }
        assert!(!legacy.exists());
        assert!(store.has_object(&digest), "and nothing else moved");
        assert_eq!(store.list_refs().unwrap().len(), 1);
    }

    /// A ref is a durable claim: a failed flush while writing it — of the staged file or of a
    /// directory — is reported, never answered as an update.
    #[test]
    fn a_failed_flush_while_writing_a_ref_is_reported() {
        let store = FileObjectStore::new(scratch());
        let (digest, _) = store.put_object(&blob_bytes("x")).unwrap();
        let _guard = permguard_core::fault::inject(
            store.root().join("refs"),
            permguard_core::fault::Fault::Fsync,
        );
        let refused = update(&store, "main", None, &digest).unwrap_err();
        assert!(matches!(refused, StoreError::Backend { .. }), "{refused}");
    }

    /// The directory's flush alone: the staged file flushes, the rename lands, and the update is
    /// still refused because the directory did not flush.
    #[test]
    fn a_failed_directory_flush_while_writing_a_ref_is_reported() {
        let store = FileObjectStore::new(scratch());
        let (digest, _) = store.put_object(&blob_bytes("x")).unwrap();
        update(&store, "other", None, &digest).unwrap();
        let _guard = permguard_core::fault::inject_exact(
            store.root().join("refs"),
            permguard_core::fault::Fault::Fsync,
        );
        assert!(update(&store, "main", None, &digest).is_err());
    }

    /// The idempotent answer flushes too: the ref file and its directory, each on its own.
    #[test]
    fn an_already_current_ref_is_answered_only_after_a_flush() {
        let store = FileObjectStore::new(scratch());
        let (digest, _) = store.put_object(&blob_bytes("x")).unwrap();
        update(&store, "main", None, &digest).unwrap();
        for path in [
            store.root().join("refs"),
            store.root().join("refs").join("main"),
        ] {
            // One failure only: a retry within the call would succeed, and the call must not.
            let _guard = permguard_core::fault::inject_exact(
                &path,
                permguard_core::fault::Fault::FsyncTimes { remaining: 1 },
            );
            assert!(
                update(&store, "main", None, &digest).is_err(),
                "{}",
                path.display()
            );
        }
        assert!(matches!(
            update(&store, "main", None, &digest).unwrap(),
            RefUpdate::AlreadyCurrent(_)
        ));
    }

    /// Many pushes of one object at once: one writes, the others find it there.
    #[test]
    fn concurrent_pushes_of_one_object_write_it_once() {
        let root = scratch();
        let bytes = blob_bytes("permit(principal, action, resource);");
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (root, bytes) = (root.clone(), bytes.clone());
                std::thread::spawn(move || {
                    FileObjectStore::new(root)
                        .publish_object(&bytes)
                        .map(|(_, _, published)| published)
                })
            })
            .collect();
        let written = handles
            .into_iter()
            .map(|held| held.join().unwrap().unwrap())
            .filter(|published| *published == Landed::Written)
            .count();
        assert_eq!(written, 1);
    }

    #[test]
    fn corrupt_objects_are_detected_not_served() {
        let store = FileObjectStore::new(scratch());
        let (digest, _) = store.put_object(&blob_bytes("x")).unwrap();
        let path = store.object_path(&digest);
        fs::write(&path, b"rot").unwrap();
        assert!(matches!(
            store.get_object(&digest),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn non_canonical_bytes_never_land() {
        let store = FileObjectStore::new(scratch());
        let mut bytes = blob_bytes("x");
        bytes.push(0x00);
        assert!(store.put_object(&bytes).is_err());
    }

    #[test]
    fn ref_cas_follows_the_idempotency_table() {
        let store = FileObjectStore::new(scratch());
        let a = Digest::compute(b"a");
        let b = Digest::compute(b"b");
        let c = Digest::compute(b"c");

        // Creation: expected None, counter starts at 1, no previous state.
        let created = update(&store, "main", None, &a).unwrap();
        let first = RefState::first(a.clone());
        assert_eq!(created, RefUpdate::Updated(first.clone()));

        // Creating again against an existing ref: conflict.
        assert!(matches!(
            update(&store, "main", None, &b),
            Err(StoreError::Conflict { .. })
        ));

        // CAS a → b, naming the first state by `(counter, ref_digest)`.
        let expected = ExpectedRef {
            counter: 1,
            digest: first.ref_digest().unwrap(),
        };
        let updated = update(&store, "main", Some(&expected), &b).unwrap();
        let second = first.successor(b.clone()).unwrap();
        assert_eq!(updated, RefUpdate::Updated(second.clone()));
        assert_eq!(
            second.previous_ref_digest,
            Some(expected.digest.clone()),
            "the new state names the one it follows"
        );

        // Lost-response retry: same target, already current — success, same counter.
        let retried = update(&store, "main", Some(&expected), &b).unwrap();
        assert_eq!(retried, RefUpdate::AlreadyCurrent(second.clone()));

        // Stale expectation: conflict carrying the current state.
        match update(&store, "main", Some(&expected), &c) {
            Err(StoreError::Conflict {
                current: Some(state),
            }) => assert_eq!(state, second),
            other => panic!("expected conflict, got {other:?}"),
        }

        // The right counter under another digest is a conflict too: the digest is the state.
        let forged = ExpectedRef {
            counter: 2,
            digest: first.ref_digest().unwrap(),
        };
        assert!(matches!(
            update(&store, "main", Some(&forged), &c),
            Err(StoreError::Conflict { .. })
        ));

        // The record round-trips the previous digest.
        assert_eq!(store.read_ref("main").unwrap().unwrap(), second);

        // Lockless read sees the latest snapshot.
        assert_eq!(store.read_ref("main").unwrap().unwrap().counter, 2);
    }

    #[test]
    fn refs_list_and_signatures_cache() {
        let store = FileObjectStore::new(scratch());
        let a = Digest::compute(b"a");
        update(&store, "main", None, &a).unwrap();
        update(&store, "feature/login", None, &a).unwrap();
        let refs = store.list_refs().unwrap();
        assert_eq!(
            refs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["feature/login", "main"]
        );

        assert!(store.read_signature("main").unwrap().is_none());
        store.write_signature("main", b"envelope").unwrap();
        assert_eq!(store.read_signature("main").unwrap().unwrap(), b"envelope");
    }

    /// A ref record is read strictly: a counter of zero, a head or a previous digest that is no
    /// digest is not a ref state, and is never guessed into one.
    #[test]
    fn a_ref_record_that_is_no_ref_state_is_refused() {
        let store = FileObjectStore::new(scratch());
        let a = Digest::compute(b"a");
        update(&store, "main", None, &a).unwrap();
        let path = store.root().join("refs").join("main");
        for broken in [
            format!("{{\"version\":1,\"head\":\"{a}\",\"counter\":0}}\n"),
            "{\"version\":1,\"head\":\"sha256:zz\",\"counter\":1}\n".to_owned(),
            format!("{{\"version\":1,\"head\":\"{a}\",\"counter\":2,\"previous\":\"x\"}}\n"),
        ] {
            fs::write(&path, &broken).unwrap();
            assert!(
                matches!(store.read_ref("main"), Err(StoreError::Backend { .. })),
                "{broken}"
            );
        }
        // Today's record, with no previous digest, reads as a state without one.
        fs::write(
            &path,
            format!("{{\"version\":1,\"head\":\"{a}\",\"counter\":3}}\n"),
        )
        .unwrap();
        let legacy = store.read_ref("main").unwrap().unwrap();
        assert_eq!((legacy.counter, legacy.previous_ref_digest), (3, None));
    }

    #[test]
    fn invalid_ref_names_are_refused_everywhere() {
        let store = FileObjectStore::new(scratch());
        let a = Digest::compute(b"a");
        for bad in ["../escape", "UPPER", "a//b", ""] {
            assert!(update(&store, bad, None, &a).is_err(), "accepted: {bad}");
            assert!(store.read_ref(bad).is_err());
        }
    }
}
