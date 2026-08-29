// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where events are kept, and how a tenant's are found without reading anybody else's.
//!
//! # Two physical layouts, on purpose
//!
//! ```text
//! streams/<zone>/<ledger>/<class>/<producer>/<instance>/   the producer's own chain
//! views/<zone>/<ledger>/                                   what one tenant may read
//! ```
//!
//! The stream is the evidence: one producer's records in one causal order, with the chain that
//! links them. The view is what a tenant is served from, and it is a *physical* copy rather than a
//! filter applied at read time — because a filter is a promise about a code path, and a directory
//! is a promise about the filesystem. A read of one tenant's view cannot return another's records
//! by any bug that is not also a bug in `open`.
//!
//! # The event-type index, and why it is positions rather than copies
//!
//! Listing one event type must not scan and decode every other type retained for a ledger. Two
//! ways to arrange that: copy each record into a per-type view, or keep an index of where they
//! are. Copies double the bytes and add a second thing that can disagree with the first; positions
//! are small, and are rebuildable from the segments, which stay authoritative.
//!
//! So each view keeps `index/<type>.idx`: one line per record of that type, naming the segment and
//! the line within it. Sequential to append, sequential to scan, and a corrupt or missing index
//! costs a rebuild rather than an answer.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use permguard_core::Jwk;
use permguard_events::record::GENESIS;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The file a stream's watermarks live in.
pub const STATE_FILE: &str = "STATE";
/// Where the public keys a batch was signed under are archived.
pub const KEYS_DIRECTORY: &str = "verification-keys";
/// How much one segment holds before the next is started.
pub const SEGMENT_RECORDS: u64 = 10_000;

/// What the store knows about one producer stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamState {
    /// The highest **contiguous durable** sequence. Never the highest accepted.
    ///
    /// The producer deletes its own copy by this number, so a number with a hole behind it is how
    /// a gap becomes permanent.
    pub acked: u64,
    /// The digest at that point, which the next record must name.
    pub head: String,
    /// Set when the stream was closed permanently, and why.
    ///
    /// A closed stream never accepts another record. What is stored stays exactly as it is, as
    /// evidence: repairing history would be indistinguishable, to a later auditor, from an
    /// attacker doing the same.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub closed: Option<String>,
}

impl StreamState {
    fn fresh() -> Self {
        Self {
            acked: 0,
            head: GENESIS.to_owned(),
            closed: None,
        }
    }
}

/// Which records a reader is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// One producer's whole stream — the privileged, deployment-wide read.
    Stream {
        zone: String,
        ledger: String,
        class: String,
        producer: String,
        instance: String,
    },
    /// One tenant's records, merged from every producer that contributed.
    Tenant { zone: String, ledger: String },
}

impl Scope {
    /// A stable name for this scope, which an offset is bound to.
    pub fn key(&self) -> String {
        match self {
            Self::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            } => format!("stream:{zone}:{ledger}:{class}:{producer}:{instance}"),
            Self::Tenant { zone, ledger } => format!("tenant:{zone}:{ledger}"),
        }
    }
}

/// The file whose lock says who owns this store.
pub const LOCK_FILE: &str = "LOCK";

/// Takes the store's exclusive lock, or refuses.
///
/// # Why the filesystem and not this process's discipline
///
/// Ingest is read-check-append across several files — a producer stream, a tenant view, an
/// envelope, a checkpoint — and the per-stream gate inside this store is what keeps two batches
/// from interleaving that sequence. A gate is a `Mutex` in one process's memory, so it says
/// nothing at all about a *second* process opening the same directory: two planes pointed at one
/// volume, a rolling restart whose old pod has not exited, an operator running a second binary to
/// look at something. Each would hold its own gate, see the other's writes only when it happened
/// to re-read, and interleave exactly the sequence the gate exists to serialise.
///
/// So the rule is the filesystem's: one process owns a store, and the second is refused at open
/// with the path in the message rather than corrupting it quietly.
fn lock_exclusively(path: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.try_lock().map_err(|_| {
        anyhow::anyhow!(
            "the event store at {} is held by another process: one writer owns a store, and two \
             would interleave the read-check-append that ingest is",
            path.display()
        )
    })?;

    Ok(file)
}

/// The store, rooted at one directory.
pub struct EventStore {
    root: PathBuf,
    /// Held for the store's lifetime: dropping it is what releases the directory.
    _lock: fs::File,
    /// One gate per stream, held for the whole of an ingest.
    ///
    /// Ingest is read-check-append across several files, and two batches for one stream
    /// interleaving that sequence would corrupt exactly what this store exists to keep whole. A
    /// well-behaved shipper is sequential; the gate is for the day something else is not. Streams
    /// stay independent, so one slow producer does not queue another's batches.
    gates:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<std::sync::Mutex<()>>>>,
}

impl EventStore {
    /// Opens the store rooted at `directory`.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let root = directory.into();
        for held in ["streams", "views", KEYS_DIRECTORY] {
            fs::create_dir_all(root.join(held)).context("creating the event store")?;
        }
        let lock = lock_exclusively(&root.join(LOCK_FILE))?;

        Ok(Self {
            root,
            _lock: lock,
            gates: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Where this store keeps everything.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The write gate of one stream. Held for the whole of an ingest.
    pub fn gate(&self, stream: &permguard_events::Stream) -> std::sync::Arc<std::sync::Mutex<()>> {
        let key = stream_key(stream);
        let mut gates = match self.gates.lock() {
            Ok(gates) => gates,
            Err(poisoned) => poisoned.into_inner(),
        };

        std::sync::Arc::clone(gates.entry(key).or_default())
    }

    /// Where one producer stream's files live.
    pub fn stream_path(&self, stream: &permguard_events::Stream) -> Result<PathBuf> {
        let mut path = self.root.join("streams");
        for segment in [
            stream.zone.as_str(),
            stream.ledger.as_str(),
            stream.producer.class.as_str(),
            stream.producer.id.as_str(),
            stream.producer.instance.as_str(),
        ] {
            path.push(safe(segment)?);
        }

        Ok(path)
    }

    /// Where one tenant's view lives.
    pub fn view_path(&self, zone: &str, ledger: &str) -> Result<PathBuf> {
        Ok(self
            .root
            .join("views")
            .join(safe(zone)?)
            .join(safe(ledger)?))
    }

    /// The directory a scope is read from.
    pub fn scope_path(&self, scope: &Scope) -> Result<PathBuf> {
        match scope {
            Scope::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            } => self.stream_path(&permguard_events::Stream {
                producer: permguard_events::Producer {
                    class: class.clone(),
                    id: producer.clone(),
                    instance: instance.clone(),
                },
                zone: zone.clone(),
                ledger: ledger.clone(),
            }),
            Scope::Tenant { zone, ledger } => self.view_path(zone, ledger),
        }
    }

    /// What the store knows about one stream.
    pub fn stream_state(&self, stream: &permguard_events::Stream) -> Result<StreamState> {
        let path = self.stream_path(stream)?.join(STATE_FILE);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("reading a stream's state"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(StreamState::fresh()),
            Err(error) => Err(error).context("reading a stream's state"),
        }
    }

    /// Appends one record verbatim, to its producer's stream and to its tenant's view.
    ///
    /// Nothing here is acknowledged: durability is a separate, explicit step, because the producer
    /// is about to delete its only other copy on the strength of it.
    pub fn append(&self, stream: &permguard_events::Stream, record: &Value) -> Result<()> {
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("a record with no `seq`"))?;
        let event_type = record
            .get("event_type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("a record with no `event_type`"))?;

        // Verbatim. A re-rendered record has a different digest, and a digest that does not match
        // is indistinguishable from tampering.
        let line = render(record)?;

        let stream_directory = self.stream_path(stream)?;
        fs::create_dir_all(&stream_directory).context("creating a stream directory")?;
        let (segment, line_number) = append_line(&segment_for(&stream_directory, seq)?, &line)?;
        index(&stream_directory, event_type, segment, line_number)?;

        let view = self.view_path(&stream.zone, &stream.ledger)?;
        fs::create_dir_all(&view).context("creating a tenant view")?;
        let (segment, line_number) = append_line(&segment_for(&view, seq)?, &line)?;
        index(&view, event_type, segment, line_number)?;

        Ok(())
    }

    /// Keeps the signed envelope that attests a range of one stream.
    pub fn keep_envelope(
        &self,
        stream: &permguard_events::Stream,
        first_seq: u64,
        signature: &Value,
    ) -> Result<()> {
        let path = self
            .stream_path(stream)?
            .join(format!("batch-{first_seq:020}.jws"));
        fs::create_dir_all(path.parent().unwrap_or(&self.root)).context("creating a stream")?;
        let bytes = serde_json::to_vec(signature).context("rendering an envelope")?;
        fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;

        Ok(())
    }

    /// Every envelope of one stream, oldest first.
    pub fn envelopes(&self, stream: &permguard_events::Stream) -> Result<Vec<Value>> {
        let directory = self.stream_path(stream)?;
        let mut found: Vec<(String, Value)> = Vec::new();
        let Ok(entries) = fs::read_dir(&directory) else {
            return Ok(Vec::new());
        };
        for entry in entries {
            let entry = entry.context("listing a stream")?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("batch-") || !name.ends_with(".jws") {
                continue;
            }
            let bytes = fs::read(entry.path()).context("reading a batch envelope")?;
            if let Ok(value) = serde_json::from_slice(&bytes) {
                found.push((name, value));
            }
        }
        found.sort_by(|left, right| left.0.cmp(&right.0));

        Ok(found.into_iter().map(|(_, value)| value).collect())
    }

    /// Archives the public key a batch was signed under, the first time it is seen.
    ///
    /// A batch signed today must still verify after that key has been rotated a dozen times, and
    /// the producer's published set only carries what is current. Public material only: nothing
    /// this store holds could sign anything.
    pub fn archive_key(&self, key: &Jwk) -> Result<()> {
        let path = self
            .root
            .join(KEYS_DIRECTORY)
            .join(format!("{}.json", safe(&key.kid)?));
        // A `kid` is a label its producer chose, not a digest of the key it names — so two
        // different keys can carry one. Taking "the file is already there" as "the same key is
        // already archived" would keep the first and silently verify later batches against it,
        // which is a wrong answer in both directions: evidence signed by the second key would fail
        // to verify, and the archive would attest to a key that never signed what it is filed
        // under. Refused, so the conflict is somebody's to resolve rather than the store's to
        // guess.
        if path.exists() {
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let held: Jwk = serde_json::from_slice(&bytes)
                .with_context(|| format!("reading the archived key {}", path.display()))?;
            if held == *key {
                return Ok(());
            }

            anyhow::bail!(
                "the key id `{}` is already archived with different material: a `kid` is a label \
                 and not a digest, so two keys can claim one, and this store cannot say which of \
                 them signed what it holds",
                key.kid
            );
        }
        let bytes = serde_json::to_vec_pretty(key).context("rendering a verification key")?;
        fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;

        Ok(())
    }

    /// Every archived verification key, for a reader checking an old batch.
    pub fn archived_keys(&self) -> Result<Vec<Jwk>> {
        let mut keys = Vec::new();
        let directory = self.root.join(KEYS_DIRECTORY);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            // Never archived anything: an empty archive, which is a legitimate state.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(keys),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", directory.display()))?;
            let path = entry.path();
            // Read and parsed, not `filter_map`ped. Skipping an unreadable key would turn "this
            // archive is damaged" into "this key was never archived", and the batch it verifies
            // would then be refused as unattributable — a corruption reported as somebody else's
            // bad signature.
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let key = serde_json::from_slice(&bytes)
                .with_context(|| format!("reading the archived key {}", path.display()))?;
            keys.push(key);
        }

        Ok(keys)
    }

    /// Discards whatever was written above the acknowledged point.
    ///
    /// Records above `acked` were written and never confirmed, so the producer does not know they
    /// are here and will resend them. Keeping them would either duplicate a sequence or raise a
    /// conflict against bytes nobody ever promised — so they are scratch, and the batch that comes
    /// next is authoritative for that range.
    pub fn rollback_unacked(&self, stream: &permguard_events::Stream, acked: u64) -> Result<u64> {
        let mut dropped = 0;
        for directory in [
            self.stream_path(stream)?,
            self.view_path(&stream.zone, &stream.ledger)?,
        ] {
            if !directory.exists() {
                continue;
            }
            for (first, path) in segments_in(&directory)? {
                if first > acked {
                    dropped += lines_in(&path)?;
                    fs::remove_file(&path).context("removing an unacknowledged segment")?;
                    continue;
                }
                dropped += truncate_above(&path, acked)?;
            }
            // The index names positions inside those segments, so it is rebuilt rather than
            // trusted: an entry pointing past a truncated segment would return a record that no
            // longer exists.
            rebuild_index(&directory)?;
        }

        Ok(dropped)
    }

    /// Flushes everything and records the number the producer may delete by.
    pub fn acknowledge(
        &self,
        stream: &permguard_events::Stream,
        acked: u64,
        head: &str,
    ) -> Result<StreamState> {
        let directory = self.stream_path(stream)?;
        flush_tree(&directory)?;
        flush_tree(&self.view_path(&stream.zone, &stream.ledger)?)?;

        let mut state = self.stream_state(stream)?;
        state.acked = acked;
        state.head = head.to_owned();
        self.write_state(&directory, &state)?;

        Ok(state)
    }

    /// Closes a stream permanently, and says why.
    pub fn close(&self, stream: &permguard_events::Stream, reason: &str) -> Result<()> {
        let directory = self.stream_path(stream)?;
        fs::create_dir_all(&directory).context("creating a stream directory")?;
        let mut state = self.stream_state(stream)?;
        state.closed = Some(reason.to_owned());

        self.write_state(&directory, &state)
    }

    fn write_state(&self, directory: &Path, state: &StreamState) -> Result<()> {
        fs::create_dir_all(directory).context("creating a stream directory")?;
        let bytes = serde_json::to_vec_pretty(state).context("rendering a stream's state")?;
        let temporary = directory.join("STATE.writing");
        fs::write(&temporary, bytes).context("writing a stream's state")?;
        fs::rename(&temporary, directory.join(STATE_FILE)).context("writing a stream's state")?;

        Ok(())
    }

    /// The segments of one scope, oldest first.
    pub fn segments(&self, scope: &Scope) -> Result<Vec<(u64, PathBuf)>> {
        segments_in(&self.scope_path(scope)?)
    }

    /// The positions of one event type inside a scope, in order.
    ///
    /// The whole point of the index: a reader asking for one type walks these rather than every
    /// record the ledger retains.
    pub fn positions_of(&self, scope: &Scope, event_type: &str) -> Result<Vec<(u64, u64)>> {
        read_index(&self.scope_path(scope)?, event_type)
    }

    /// Every event type a scope holds at least one record of.
    pub fn types_in(&self, scope: &Scope) -> Result<Vec<String>> {
        let directory = self.scope_path(scope)?.join("index");
        let mut found = Vec::new();
        let Ok(entries) = fs::read_dir(&directory) else {
            return Ok(found);
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(slug) = name.strip_suffix(".idx")
                && let Some(held) = unslug(slug)
            {
                found.push(held);
            }
        }
        found.sort();

        Ok(found)
    }

    /// Every tenant ledger this store holds events for.
    pub fn ledgers(&self) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let Ok(zones) = fs::read_dir(self.root.join("views")) else {
            return found;
        };
        for zone in zones.flatten() {
            let Ok(name) = zone.file_name().into_string() else {
                continue;
            };
            let Ok(ledgers) = fs::read_dir(zone.path()) else {
                continue;
            };
            for ledger in ledgers.flatten() {
                if let Ok(held) = ledger.file_name().into_string() {
                    found.push((name.clone(), held));
                }
            }
        }
        found.sort();

        found
    }
}

/// One stream, as a single key.
fn stream_key(stream: &permguard_events::Stream) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        stream.zone,
        stream.ledger,
        stream.producer.class,
        stream.producer.id,
        stream.producer.instance
    )
}

/// A path segment that is one segment.
///
/// Names reach this store from a signed envelope, which means they are attributable but not
/// harmless: a producer whose id contained `../` would write outside its own directory. Refused
/// rather than sanitized, because a sanitized name is a different name and two producers could
/// then sanitize to one.
fn safe(name: &str) -> Result<String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(anyhow!(
            "`{name}` is not a name this store can make a directory of"
        ));
    }

    Ok(name.to_owned())
}

/// The segment a sequence belongs in.
fn segment_for(directory: &Path, seq: u64) -> Result<PathBuf> {
    let first = seq.saturating_sub(1) / SEGMENT_RECORDS * SEGMENT_RECORDS + 1;

    Ok(directory.join(format!("seg-{first:020}.events")))
}

/// Reads a file, or says it is not there.
///
/// `None` means the file does not exist, which is a legitimate "nothing here yet". Every other
/// failure — a permission, a bad disk, a truncated read — is an error and not an absence.
/// Collapsing the two is how a store that cannot be read answers "this ledger is empty", which is
/// a wrong answer rather than an unavailable one, and one a caller acts on.
fn read_or_absent(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// The segments of a directory, oldest first.
pub fn segments_in(directory: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut found = Vec::new();
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        // A scope nothing has written to yet holds no segments.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        // Anything else is this store failing to read itself. Answering "no segments" would report
        // an unreadable ledger as an empty one — to a reader, to retention, and to a sweep that
        // would then believe there was nothing to keep.
        Err(error) => {
            return Err(error).with_context(|| format!("listing {}", directory.display()));
        }
    };
    for entry in entries {
        let entry = entry.context("listing a scope")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name
            .strip_prefix("seg-")
            .and_then(|held| held.strip_suffix(".events"))
        else {
            continue;
        };
        let Ok(first) = rest.parse::<u64>() else {
            continue;
        };
        found.push((first, entry.path()));
    }
    found.sort_by_key(|(first, _)| *first);

    Ok(found)
}

/// One record as the one line it is stored as.
fn render(record: &Value) -> Result<String> {
    let mut line = serde_json::to_string(record).context("rendering a record")?;
    line.push('\n');

    Ok(line)
}

/// Appends a line, and says which segment and line it became.
fn append_line(path: &Path, line: &str) -> Result<(u64, u64)> {
    let existing = lines_in(path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;

    let first = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("seg-"))
        .and_then(|name| name.strip_suffix(".events"))
        .and_then(|name| name.parse::<u64>().ok())
        .unwrap_or_default();

    Ok((first, existing))
}

/// How many records a segment holds.
pub fn lines_in(path: &Path) -> Result<u64> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().filter(|line| !line.is_empty()).count() as u64),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error).context("reading a segment"),
    }
}

/// Drops every record of a segment above `acked`, and says how many went.
fn truncate_above(path: &Path, acked: u64) -> Result<u64> {
    let Some(text) = read_or_absent(path)? else {
        return Ok(0);
    };
    let mut kept = String::new();
    let mut dropped = 0;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let seq = serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|record| record.get("seq").and_then(Value::as_u64))
            .unwrap_or_default();
        if seq > acked {
            dropped += 1;
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    if dropped > 0 {
        fs::write(path, kept).context("truncating a segment")?;
    }

    Ok(dropped)
}

/// The index file of one event type inside a scope.
fn index_path(directory: &Path, event_type: &str) -> PathBuf {
    directory
        .join("index")
        .join(format!("{}.idx", slug(event_type)))
}

/// A registered type name as a file name.
///
/// Reversible, so the set of indexed types can be listed back without a second file recording
/// them. Only `.` and `/` need replacing in a registered name, and `.` is the only one that occurs.
fn slug(event_type: &str) -> String {
    event_type.replace('/', "_").replace('.', "-")
}

fn unslug(slug: &str) -> Option<String> {
    (!slug.is_empty()).then(|| slug.replace('-', "."))
}

/// Records where one record of `event_type` sits.
fn index(directory: &Path, event_type: &str, segment: u64, line: u64) -> Result<()> {
    let path = index_path(directory, event_type);
    fs::create_dir_all(path.parent().unwrap_or(directory)).context("creating an index")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(file, "{segment}:{line}").with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

/// The positions of one event type, in order.
fn read_index(directory: &Path, event_type: &str) -> Result<Vec<(u64, u64)>> {
    let path = index_path(directory, event_type);
    let Some(text) = read_or_absent(&path)? else {
        return Ok(Vec::new());
    };
    let mut positions = Vec::new();
    for (number, line) in text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
    {
        // A damaged index entry is not a missing one. Dropping it silently would hide records the
        // index is the only cheap way to find, and a filtered read would answer "no such events"
        // about events the segments hold.
        let held = line
            .split_once(':')
            .and_then(|(segment, offset)| Some((segment.parse().ok()?, offset.parse().ok()?)));
        let Some(held) = held else {
            anyhow::bail!(
                "the index {} is damaged at line {}: rebuild it from the segments",
                path.display(),
                number + 1
            );
        };
        positions.push(held);
    }

    Ok(positions)
}

/// Rebuilds every index of a scope from its segments.
///
/// The segments are authoritative; the index is a convenience that must never be able to disagree
/// with them. Rebuilding is what makes that true after a truncation, and what makes a lost index
/// a cost rather than a wrong answer.
pub fn rebuild_index(directory: &Path) -> Result<()> {
    let index = directory.join("index");
    let _ = fs::remove_dir_all(&index);
    let mut positions: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    for (first, path) in segments_in(directory)? {
        // A segment that cannot be read cannot be indexed, and an index built as though it were
        // empty is an index that says those records do not exist.
        let Some(text) = read_or_absent(&path)? else {
            continue;
        };
        for (line_number, line) in text.lines().filter(|line| !line.is_empty()).enumerate() {
            let record: Value = serde_json::from_str(line).with_context(|| {
                format!(
                    "reading the record at line {} of {}",
                    line_number + 1,
                    path.display()
                )
            })?;
            let Some(event_type) = record.get("event_type").and_then(Value::as_str) else {
                continue;
            };
            positions
                .entry(event_type.to_owned())
                .or_default()
                .push((first, line_number as u64));
        }
    }
    if positions.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(&index).context("creating an index")?;
    for (event_type, held) in positions {
        let body: String = held
            .into_iter()
            .map(|(segment, line)| format!("{segment}:{line}\n"))
            .collect();
        fs::write(index_path(directory, &event_type), body).context("writing an index")?;
    }

    Ok(())
}

/// `fsync`s every file of a directory, and the directory itself.
fn flush_tree(directory: &Path) -> Result<()> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            flush_tree(&path)?;
            continue;
        }
        if let Ok(file) = fs::File::open(&path) {
            file.sync_all()
                .with_context(|| format!("flushing {}", path.display()))?;
        }
    }
    if let Ok(handle) = fs::File::open(directory) {
        // A directory `fsync` is what makes a *newly created* file survive: the file's own flush
        // does not persist the entry that names it.
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Reads up to `limit` records of a segment, from `position`.
pub fn read_segment(path: &Path, position: u64, limit: usize) -> Result<(Vec<Value>, u64)> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), position));
        }
        Err(error) => return Err(error).context("reading a segment"),
    };
    let mut records = Vec::new();
    let mut offset = position;
    for line in text
        .lines()
        .skip(usize::try_from(position).unwrap_or(usize::MAX))
    {
        if records.len() >= limit {
            break;
        }
        offset += 1;
        if line.is_empty() {
            continue;
        }
        records.push(serde_json::from_str(line).context("reading a record")?);
    }

    Ok((records, offset))
}

/// One record of a segment, by line.
pub fn read_line(path: &Path, line: u64) -> Result<Option<Value>> {
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(None);
    };
    let Some(held) = text
        .lines()
        .filter(|line| !line.is_empty())
        .nth(usize::try_from(line).unwrap_or(usize::MAX))
    else {
        return Ok(None);
    };

    Ok(Some(
        serde_json::from_str(held).context("reading a record")?,
    ))
}
