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
//! Objects are written tmp + fsync + rename and verified canonical before
//! they land; writing the same digest twice is a no-op by construction.
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
                            return Err(StoreError::Incompatible {
                                found: "unversioned".to_owned(),
                            });
                        }
                        write_durable(&path, format!("{FORMAT}\n").as_bytes())
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
        let hex = digest.to_string();
        let hex = &hex["sha256:".len()..];
        self.root.join("objects").join(&hex[..2]).join(&hex[2..])
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
    /// then write tmp + fsync + rename. Returns the digest and the decoded
    /// object. Storing bytes already present is a success and a no-op.
    pub fn put_object(&self, bytes: &[u8]) -> Result<(Digest, Object)> {
        if bytes.len() > limits::MAX_OBJECT_BYTES {
            return Err(ObjectError::Limit("object bytes").into());
        }
        self.check_format()?;
        let decoded = object::decode(bytes)?;
        let digest = Digest::compute(bytes);
        let path = self.object_path(&digest);
        if !path.exists() {
            write_durable(&path, &compress::deflate(bytes))?;
        }
        Ok((digest, decoded))
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
        write_durable(&self.ref_path(name), render_ref(&state).as_bytes())?;
        Ok(RefUpdate::Updated(state))
    }

    /// Store the signed head statement for a ref — a cache, replaced on
    /// every update, verified against the current ref before being served.
    pub fn write_signature(&self, name: &str, envelope: &[u8]) -> Result<()> {
        grammar::validate_ref_name(name)?;
        write_durable(&self.signature_path(name), envelope)
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

/// Write temp → fsync temp → atomic rename → fsync the containing directory:
/// the durability sequence the specification requires before acknowledging.
fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path.parent().ok_or_else(|| StoreError::Backend {
        detail: format!("{} has no parent directory", path.display()),
    })?;
    fs::create_dir_all(directory).map_err(|e| backend("creating directory", e))?;

    let staged = path.with_extension("tmp");
    let mut file = fs::File::create(&staged).map_err(|e| backend("staging write", e))?;
    file.write_all(bytes)
        .map_err(|e| backend("staging write", e))?;
    file.sync_all()
        .map_err(|e| backend("fsync of staged file", e))?;
    drop(file);

    fs::rename(&staged, path).map_err(|e| backend("atomic replace", e))?;

    // Make the rename itself durable. Directory fsync is best-effort where
    // the platform refuses to open directories for writing.
    if let Ok(dir) = fs::File::open(directory) {
        let _ = dir.sync_all();
    }
    Ok(())
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
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "tmp") {
            continue;
        }
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
