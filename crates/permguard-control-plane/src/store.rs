// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The object store of one ledger on the local filesystem.
//!
//! ```text
//! <ledger>/objects/ab/cdef…   one file per object, digest-fanout, immutable
//! <ledger>/refs/<name>        JSON: the head digest + the monotonic counter
//! <ledger>/signatures/…       COSE_Sign1 head statements, a replaceable cache
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

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use permguard_host::storage::write::{Published, publish_immutable};
use permguard_host::storage::{Dir, StorageError};
use permguard_objects::compress;
use permguard_objects::digest::Digest;
use permguard_objects::grammar::{self, GrammarError};
use permguard_objects::limits;
use permguard_objects::object::{self, Object, ObjectError};

/// One object as it sits on the shelf: what it is, how big, and how old.
///
/// Age is the file's, which is exactly right for the only question asked of
/// it: *could this still belong to a transfer in flight?*
#[derive(Debug, Clone)]
pub struct StoredObject {
    pub digest: Digest,
    pub bytes: u64,
    pub modified: std::time::SystemTime,
}

/// The state of one ref: what the specification calls `(head, counter)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefState {
    pub head: Digest,
    pub counter: u64,
}

/// The outcome of a compare-and-swap ref update, per the idempotency table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefUpdate {
    /// The head moved: a genuine update, counter incremented.
    Updated(RefState),
    /// The current head already equals the new head: a retry landed —
    /// success, counter untouched.
    AlreadyCurrent(RefState),
}

/// Why the store refused.
#[derive(Debug, Clone)]
pub enum StoreError {
    /// The object bytes were rejected by the model (non-canonical, over a
    /// limit, wrong schema).
    Object(ObjectError),
    /// A name failed its grammar.
    Grammar(GrammarError),
    /// The CAS found a different current head. Carries what is current, so
    /// the caller can answer with the truth.
    Conflict { current: Option<RefState> },
    /// A stored object's bytes no longer hash to its name: detection, not
    /// recovery — the caller reports it and recovery comes from replicas.
    Corrupt { digest: Digest },
    /// The on-disk layout was written by a different version: refused,
    /// never reinterpreted.
    Incompatible { found: String },
    /// The filesystem failed.
    Backend { detail: String },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Object(e) => write!(f, "object rejected: {e}"),
            StoreError::Grammar(e) => write!(f, "name rejected: {e}"),
            StoreError::Conflict { .. } => write!(f, "the ref moved: compare-and-swap conflict"),
            StoreError::Corrupt { digest } => write!(f, "stored object {digest} is corrupt"),
            StoreError::Incompatible { found } => write!(
                f,
                "the store layout is `{found}`; this build speaks `{FORMAT}`"
            ),
            StoreError::Backend { detail } => write!(f, "the object store failed: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ObjectError> for StoreError {
    fn from(e: ObjectError) -> Self {
        StoreError::Object(e)
    }
}

impl From<GrammarError> for StoreError {
    fn from(e: GrammarError) -> Self {
        StoreError::Grammar(e)
    }
}

fn backend(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Backend {
        detail: format!("{context}: {error}"),
    }
}

type Result<T> = std::result::Result<T, StoreError>;

/// The one layout this build reads and writes, pinned in `FORMAT`.
pub const FORMAT: &str = "1";

/// The object store of one ledger directory.
pub struct FileObjectStore {
    root: PathBuf,
    /// Serialises ref mutations; object writes are idempotent and need none.
    refs_lock: Mutex<()>,
    /// The `FORMAT` gate, checked once per store lifetime.
    format: OnceLock<Result<()>>,
}

impl FileObjectStore {
    /// Opens the store over a ledger directory, creating nothing until
    /// something is stored.
    pub fn new(ledger_directory: impl Into<PathBuf>) -> Self {
        Self {
            root: ledger_directory.into(),
            refs_lock: Mutex::new(()),
            format: OnceLock::new(),
        }
    }

    /// The `FORMAT` gate: a fresh directory gets the pin written; a pinned
    /// directory must match; a populated directory without a pin was written
    /// by an older layout — refused with what to do about it.
    fn check_format(&self) -> Result<()> {
        self.format
            .get_or_init(|| {
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
            })
            .clone()
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

    /// Whether an object is present — the negotiation primitive. Presence,
    /// not integrity: a file stat, nothing more.
    pub fn has_object(&self, digest: &Digest) -> bool {
        self.object_path(digest).exists()
    }

    /// Ingest one object: canonical decode, limits, grammars — fail-closed —
    /// then publish it without replacement. Returns the digest and the decoded
    /// object. Storing content already present is a success and a no-op.
    pub fn put_object(&self, bytes: &[u8]) -> Result<(Digest, Object)> {
        self.publish_object(bytes)
            .map(|(digest, decoded, _)| (digest, decoded))
    }

    /// The same, and whether it wrote: [`Published::AlreadyThere`] when the
    /// object was already stored, which then writes nothing at all.
    ///
    /// Published through the storage library's no-replace path (H-06): a
    /// flushed temporary is hard-linked to the object's name, which fails when
    /// the name exists. Two pushes of one object at once end with one write and
    /// one no-op; a name already holding *different* content — whose bytes no
    /// longer decompress to this object — is [`StoreError::Corrupt`], and the
    /// existing file is left byte-for-byte as it was.
    pub fn publish_object(&self, bytes: &[u8]) -> Result<(Digest, Object, Published)> {
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
        Ok((digest, decoded, published))
    }

    /// Read one object, verifying on the way out that the bytes still hash
    /// to their name — corruption is detected here, never served silently.
    pub fn get_object(&self, digest: &Digest) -> Result<Option<Vec<u8>>> {
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
    pub fn read_ref(&self, name: &str) -> Result<Option<RefState>> {
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

    /// Every object in the store: its digest, how old the file is, and how
    /// many bytes it occupies.
    ///
    /// A directory walk and one `stat` per file — nothing is read and nothing
    /// is decompressed, because the sweep that uses this decides by
    /// reachability and age, never by content. A name that is not a digest is
    /// skipped rather than guessed at: a stray file in the fanout is somebody
    /// else's, and this is not the place to have an opinion about it.
    pub fn list_objects(&self) -> Result<Vec<StoredObject>> {
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
    pub fn remove_object(&self, digest: &Digest) -> Result<u64> {
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
    pub fn make_ref_durable(&self, name: &str) -> Result<()> {
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
    pub fn make_durable(&self, digests: &std::collections::BTreeSet<Digest>) -> Result<()> {
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
    pub fn sweep_temporaries(&self, older_than: std::time::Duration) -> Result<usize> {
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

    /// List every ref, by walking `refs/`.
    pub fn list_refs(&self) -> Result<Vec<(String, RefState)>> {
        let mut out = Vec::new();
        let base = self.root.join("refs");
        collect_refs(&base, &base, &mut out)?;
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// The idempotent compare-and-swap of the specification:
    ///
    /// | current head          | result                                   |
    /// |-----------------------|------------------------------------------|
    /// | `== new`              | `AlreadyCurrent`, counter untouched      |
    /// | `== expected`         | update `(head, counter)` atomically      |
    /// | anything else         | `Conflict`, carrying what is current     |
    ///
    /// `expected = None` is the creation case: it succeeds only while the
    /// ref does not exist, and the counter starts at 1.
    pub fn update_ref(
        &self,
        name: &str,
        expected: Option<&Digest>,
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

        let matches = match (expected, &current) {
            (None, None) => true,
            (Some(expected), Some(state)) => state.head == *expected,
            _ => false,
        };
        if !matches {
            return Err(StoreError::Conflict { current });
        }

        let counter = current.as_ref().map_or(1, |state| state.counter + 1);
        let state = RefState {
            head: new.clone(),
            counter,
        };
        write_durable(
            &self.root,
            &format!("refs/{name}"),
            render_ref(&state).as_bytes(),
        )?;
        Ok(RefUpdate::Updated(state))
    }

    /// Store the signed head statement for a ref — a cache, replaced on
    /// every update, verified against the current ref before being served.
    pub fn write_signature(&self, name: &str, envelope: &[u8]) -> Result<()> {
        grammar::validate_ref_name(name)?;
        write_durable(&self.root, &format!("signatures/{name}"), envelope)
    }

    /// Read the cached statement envelope for a ref, if any.
    pub fn read_signature(&self, name: &str) -> Result<Option<Vec<u8>>> {
        grammar::validate_ref_name(name)?;
        match fs::read(self.signature_path(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(backend("reading signature", error)),
        }
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
                why: "each ref's head and monotonic counter",
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
fn write_durable(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
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
    let temp = permguard_host::storage::dir::temp_name();
    let staged = dir.child_path(&temp);
    let written = (|| {
        let mut file = dir
            .create_exclusive(&temp)
            .map_err(|error| storage("staging write", error))?;
        permguard_core::fault::write(&staged, bytes.len(), || file.write_all(bytes))
            .map_err(|e| backend("staging write", e))?;
        permguard_core::fault::sync(&staged, || file.sync_all())
            .map_err(|e| backend("fsync of staged file", e))?;
        drop(file);
        dir.rename(&temp, name)
            .map_err(|error| storage("atomic replace", error))?;
        dir.sync()
            .map_err(|error| storage("flushing the directory", error))
    })();
    if written.is_err() {
        let _ = dir.unlink(&temp);
    }
    written
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

fn render_ref(state: &RefState) -> String {
    format!(
        "{{\"version\":1,\"head\":\"{}\",\"counter\":{}}}\n",
        state.head, state.counter
    )
}

/// Parse the ref record without a JSON dependency: the format is ours, one
/// line, three fields, written only by `render_ref`.
fn parse_ref(text: &str) -> Option<RefState> {
    let head_key = "\"head\":\"";
    let counter_key = "\"counter\":";
    let head_start = text.find(head_key)? + head_key.len();
    let head_end = text[head_start..].find('"')? + head_start;
    let head = Digest::parse(&text[head_start..head_end]).ok()?;
    let counter_start = text.find(counter_key)? + counter_key.len();
    let counter_end = text[counter_start..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(text.len(), |i| i + counter_start);
    let counter: u64 = text[counter_start..counter_end].parse().ok()?;
    Some(RefState { head, counter })
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
                    .map(|(_, _, published)| published == Published::Written)
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
        store.update_ref("feature/login", None, &head).unwrap();
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
        let refused = store.update_ref("main", None, &digest).unwrap_err();
        assert!(matches!(refused, StoreError::Backend { .. }), "{refused}");
    }

    /// The directory's flush alone: the staged file flushes, the rename lands, and the update is
    /// still refused because the directory did not flush.
    #[test]
    fn a_failed_directory_flush_while_writing_a_ref_is_reported() {
        let store = FileObjectStore::new(scratch());
        let (digest, _) = store.put_object(&blob_bytes("x")).unwrap();
        store.update_ref("other", None, &digest).unwrap();
        let _guard = permguard_core::fault::inject_exact(
            store.root().join("refs"),
            permguard_core::fault::Fault::Fsync,
        );
        assert!(store.update_ref("main", None, &digest).is_err());
    }

    /// The idempotent answer flushes too: the ref file and its directory, each on its own.
    #[test]
    fn an_already_current_ref_is_answered_only_after_a_flush() {
        let store = FileObjectStore::new(scratch());
        let (digest, _) = store.put_object(&blob_bytes("x")).unwrap();
        store.update_ref("main", None, &digest).unwrap();
        for path in [
            store.root().join("refs"),
            store.root().join("refs").join("main"),
        ] {
            let _guard =
                permguard_core::fault::inject_exact(&path, permguard_core::fault::Fault::Fsync);
            assert!(
                store.update_ref("main", None, &digest).is_err(),
                "{}",
                path.display()
            );
        }
        assert!(matches!(
            store.update_ref("main", None, &digest).unwrap(),
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
            .filter(|published| *published == Published::Written)
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

        // Creation: expected None, counter starts at 1.
        let created = store.update_ref("main", None, &a).unwrap();
        assert_eq!(
            created,
            RefUpdate::Updated(RefState {
                head: a.clone(),
                counter: 1
            })
        );

        // Creating again against an existing ref: conflict.
        assert!(matches!(
            store.update_ref("main", None, &b),
            Err(StoreError::Conflict { .. })
        ));

        // CAS a → b.
        let updated = store.update_ref("main", Some(&a), &b).unwrap();
        assert_eq!(
            updated,
            RefUpdate::Updated(RefState {
                head: b.clone(),
                counter: 2
            })
        );

        // Lost-response retry: same target, already current — success, same counter.
        let retried = store.update_ref("main", Some(&a), &b).unwrap();
        assert_eq!(
            retried,
            RefUpdate::AlreadyCurrent(RefState {
                head: b.clone(),
                counter: 2
            })
        );

        // Stale expectation: conflict carrying the current state.
        match store.update_ref("main", Some(&a), &c) {
            Err(StoreError::Conflict {
                current: Some(state),
            }) => {
                assert_eq!(
                    state,
                    RefState {
                        head: b.clone(),
                        counter: 2
                    }
                );
            }
            other => panic!("expected conflict, got {other:?}"),
        }

        // Lockless read sees the latest snapshot.
        assert_eq!(store.read_ref("main").unwrap().unwrap().counter, 2);
    }

    #[test]
    fn refs_list_and_signatures_cache() {
        let store = FileObjectStore::new(scratch());
        let a = Digest::compute(b"a");
        store.update_ref("main", None, &a).unwrap();
        store.update_ref("feature/login", None, &a).unwrap();
        let refs = store.list_refs().unwrap();
        assert_eq!(
            refs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["feature/login", "main"]
        );

        assert!(store.read_signature("main").unwrap().is_none());
        store.write_signature("main", b"envelope").unwrap();
        assert_eq!(store.read_signature("main").unwrap().unwrap(), b"envelope");
    }

    #[test]
    fn invalid_ref_names_are_refused_everywhere() {
        let store = FileObjectStore::new(scratch());
        let a = Digest::compute(b"a");
        for bad in ["../escape", "UPPER", "a//b", ""] {
            assert!(store.update_ref(bad, None, &a).is_err(), "accepted: {bad}");
            assert!(store.read_ref(bad).is_err());
        }
    }
}
