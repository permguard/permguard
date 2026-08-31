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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use permguard_core::Jwk;
use permguard_events::record::GENESIS;
use permguard_stream::Frontier;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The file a stream's watermarks live in.
pub const STATE_FILE: &str = "STATE";
/// Where the public keys a batch was signed under are archived.
pub const KEYS_DIRECTORY: &str = "verification-keys";
/// How much one segment holds before the next is started.
pub const SEGMENT_RECORDS: u64 = 10_000;
/// The monotonic append position and producer frontier of a merged tenant view.
const VIEW_STATE_FILE: &str = "VIEW_STATE";

type TenantName = (String, String);
type ProducerPosition = (String, String, String);
type StreamIndex = BTreeMap<TenantName, BTreeSet<ProducerPosition>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ViewState {
    next: u64,
    /// Physical positions made durable and acknowledged, as a zero-based count.
    #[serde(default)]
    committed: u64,
    frontier: Frontier,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            next: 1,
            committed: 0,
            frontier: Frontier::empty(),
        }
    }
}

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

/// One bounded page of a ledger's producer streams, and whether more follow it.
#[derive(Debug, Clone)]
pub struct StreamPage {
    pub streams: Vec<permguard_events::Stream>,
    /// True when the walk stopped at the bound with positions still unvisited: the last stream's
    /// `(class, producer, instance)` is the cursor for the next page.
    pub truncated: bool,
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
    pub fn for_stream(stream: &permguard_events::Stream) -> Self {
        Self::Stream {
            zone: stream.zone.clone(),
            ledger: stream.ledger.clone(),
            class: stream.producer.class.clone(),
            producer: stream.producer.id.clone(),
            instance: stream.producer.instance.clone(),
        }
    }

    fn as_stream(&self) -> Option<permguard_events::Stream> {
        match self {
            Self::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            } => Some(permguard_events::Stream {
                producer: permguard_events::Producer {
                    class: class.clone(),
                    id: producer.clone(),
                    instance: instance.clone(),
                },
                zone: zone.clone(),
                ledger: ledger.clone(),
            }),
            Self::Tenant { .. } => None,
        }
    }

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
    /// One append/rollback gate per merged tenant view. Producer stream gates cannot protect a
    /// file that several producers share.
    view_gates:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<std::sync::Mutex<()>>>>,
    /// The acknowledged producer streams, ordered for bounded signer-manifest pagination.
    ///
    /// Rebuilt once from durable stream state at open and updated only after acknowledgement.
    /// This keeps a request from sorting the complete on-disk history every time it asks for one
    /// page.
    stream_index: std::sync::RwLock<StreamIndex>,
}

impl EventStore {
    /// Opens the store rooted at `directory`.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let root = directory.into();
        for held in ["streams", "views", KEYS_DIRECTORY] {
            fs::create_dir_all(root.join(held)).context("creating the event store")?;
        }
        let lock = lock_exclusively(&root.join(LOCK_FILE))?;
        recover_torn_segments(&root)?;
        recover_views(&root)?;
        let stream_index = discover_streams(&root)?;

        Ok(Self {
            root,
            _lock: lock,
            gates: std::sync::Mutex::new(std::collections::HashMap::new()),
            view_gates: std::sync::Mutex::new(std::collections::HashMap::new()),
            stream_index: std::sync::RwLock::new(stream_index),
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

    pub(crate) fn view_gate(
        &self,
        zone: &str,
        ledger: &str,
    ) -> std::sync::Arc<std::sync::Mutex<()>> {
        let key = format!("{zone}:{ledger}");
        let mut gates = match self.view_gates.lock() {
            Ok(gates) => gates,
            Err(poisoned) => poisoned.into_inner(),
        };

        std::sync::Arc::clone(gates.entry(key).or_default())
    }

    pub(crate) fn scope_gate(&self, scope: &Scope) -> std::sync::Arc<std::sync::Mutex<()>> {
        match scope {
            Scope::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            } => self.gate(&permguard_events::Stream {
                producer: permguard_events::Producer {
                    class: class.clone(),
                    id: producer.clone(),
                    instance: instance.clone(),
                },
                zone: zone.clone(),
                ledger: ledger.clone(),
            }),
            Scope::Tenant { zone, ledger } => self.view_gate(zone, ledger),
        }
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
    pub fn append_batch(
        &self,
        stream: &permguard_events::Stream,
        records: &[&Value],
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let view = self.view_path(&stream.zone, &stream.ledger)?;
        fs::create_dir_all(&view).context("creating a tenant view")?;
        let mut state = read_view_state(&view, &self.root)?;
        for record in records {
            self.append_one(stream, record, &view, &mut state)?;
        }
        // One derived-state commit per signed batch, not per record. The segment and index writes
        // are still flushed together by `acknowledge`; this only removes thousands of redundant
        // rename operations from a large batch.
        write_view_state(&view, &state)
    }

    fn append_one(
        &self,
        stream: &permguard_events::Stream,
        record: &Value,
        view: &Path,
        state: &mut ViewState,
    ) -> Result<()> {
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
        let stream_segment = segment_for(&stream_directory, seq)?;
        let (segment, line_number) = append_line(&stream_segment, line_in_segment(seq), &line)?;
        index(&stream_directory, event_type, segment, line_number)?;

        let view_segment = segment_for(view, state.next)?;
        let (segment, line_number) =
            append_line(&view_segment, line_in_segment(state.next), &line)?;
        index(view, event_type, segment, line_number)?;
        state.next = state.next.saturating_add(1);

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
        write_atomic(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;

        Ok(())
    }

    /// One bounded, sorted, filtered page of the producer streams this store holds for one
    /// ledger.
    ///
    /// Read from the ordered in-memory index rebuilt from durable state at startup and updated
    /// after every acknowledgement. The filesystem tree is never collected and sorted on a
    /// request path, and the answer stops as soon as one position beyond the requested page is
    /// known.
    ///
    /// Streams come back in `(class, producer, instance)` order, so `after` — the last triple of
    /// the previous page — is a stable cursor.
    #[allow(clippy::too_many_arguments)]
    pub fn producer_streams_page(
        &self,
        zone: &str,
        ledger: &str,
        class: Option<&str>,
        producer: Option<&str>,
        instance: Option<&str>,
        after: Option<(&str, &str, &str)>,
        limit: usize,
    ) -> Result<StreamPage> {
        let _ = safe(zone)?;
        let _ = safe(ledger)?;
        let index = match self.stream_index.read() {
            Ok(index) => index,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(held) = index.get(&(zone.to_owned(), ledger.to_owned())) else {
            return Ok(StreamPage {
                streams: Vec::new(),
                truncated: false,
            });
        };

        let mut streams = Vec::new();
        let mut truncated = false;
        for (held_class, held_id, held_instance) in held {
            if class.is_some_and(|wanted| held_class != wanted)
                || producer.is_some_and(|wanted| held_id != wanted)
                || instance.is_some_and(|wanted| held_instance != wanted)
                || after.is_some_and(|last| {
                    (
                        held_class.as_str(),
                        held_id.as_str(),
                        held_instance.as_str(),
                    ) <= last
                })
            {
                continue;
            }
            if streams.len() == limit {
                truncated = true;
                break;
            }
            streams.push(permguard_events::Stream::new(
                permguard_events::Producer {
                    class: held_class.clone(),
                    id: held_id.clone(),
                    instance: held_instance.clone(),
                },
                zone,
                ledger,
            ));
        }

        Ok(StreamPage { streams, truncated })
    }

    /// Records which key verified the batch starting at `first_seq`, beside the stream.
    ///
    /// The consumer's copy of the producer's signer manifest, built from what ingest actually
    /// verified against — so a verifier reading from this store can name the keys a range needs
    /// without reaching the producer, which may be gone.
    ///
    /// Called under the stream's ingest gate, like every other read-check-append here.
    pub fn note_signer(
        &self,
        stream: &permguard_events::Stream,
        first_seq: u64,
        key: &permguard_core::keys::Jwk,
    ) -> Result<()> {
        let path = self
            .stream_path(stream)?
            .join(permguard_stream::SIGNERS_FILE);
        let mut signers =
            permguard_stream::Signers::load(&path).context("reading the signer manifest")?;
        let jwk = serde_json::to_value(key).context("rendering a signer key")?;
        let changed = signers
            .observe(first_seq, &key.kid, &jwk)
            .map_err(|error| anyhow::anyhow!("recording a signer: {error}"))?;
        if changed {
            signers.save(&path).context("writing the signer manifest")?;
        }

        Ok(())
    }

    /// Validates a signer observation without changing the manifest.
    ///
    /// Ingest calls this under the stream gate before writing records or replacing an envelope.
    pub fn check_signer(
        &self,
        stream: &permguard_events::Stream,
        first_seq: u64,
        key: &permguard_core::keys::Jwk,
    ) -> Result<()> {
        let path = self
            .stream_path(stream)?
            .join(permguard_stream::SIGNERS_FILE);
        let signers =
            permguard_stream::Signers::load(&path).context("reading the signer manifest")?;
        let jwk = serde_json::to_value(key).context("rendering a signer key")?;
        signers
            .check_observation(first_seq, &key.kid, &jwk)
            .map_err(|error| anyhow::anyhow!("recording a signer: {error}"))
    }

    /// Which key signed which stretch of one stream, as this store verified it.
    pub fn signers(&self, stream: &permguard_events::Stream) -> Result<permguard_stream::Signers> {
        let path = self
            .stream_path(stream)?
            .join(permguard_stream::SIGNERS_FILE);

        permguard_stream::Signers::load(&path).context("reading the signer manifest")
    }

    /// Every envelope of one stream, oldest first.
    pub fn envelopes(&self, stream: &permguard_events::Stream) -> Result<Vec<Value>> {
        let directory = self.stream_path(stream)?;
        let mut found: Vec<(String, Value)> = Vec::new();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| format!("listing {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = entry.context("listing a stream")?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("batch-") || !name.ends_with(".jws") {
                continue;
            }
            let bytes = fs::read(entry.path()).context("reading a batch envelope")?;
            let value = serde_json::from_slice(&bytes).with_context(|| {
                format!("reading the batch envelope {}", entry.path().display())
            })?;
            found.push((name, value));
        }
        found.sort_by(|left, right| left.0.cmp(&right.0));

        Ok(found.into_iter().map(|(_, value)| value).collect())
    }

    /// The signed envelope whose sequence range contains the requested sequence.
    ///
    /// File names carry the first sequence, so only the greatest one not after the record is read.
    /// Proof generation used to parse every historical envelope for every page; this keeps the
    /// lookup proportional to directory entries and reads one payload.
    pub fn envelope_covering(
        &self,
        stream: &permguard_events::Stream,
        sequence: u64,
    ) -> Result<Option<Value>> {
        let directory = self.stream_path(stream)?;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("listing {}", directory.display()));
            }
        };
        let mut candidate: Option<(u64, PathBuf)> = None;
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", directory.display()))?;
            let name = entry.file_name();
            let Some(first) = name
                .to_str()
                .and_then(|name| name.strip_prefix("batch-"))
                .and_then(|name| name.strip_suffix(".jws"))
                .and_then(|name| name.parse::<u64>().ok())
            else {
                continue;
            };
            if first <= sequence && candidate.as_ref().is_none_or(|(held, _)| first > *held) {
                candidate = Some((first, entry.path()));
            }
        }
        let Some((_, path)) = candidate else {
            return Ok(None);
        };
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let signed = serde_json::from_slice(&bytes)
            .with_context(|| format!("reading the batch envelope {}", path.display()))?;

        Ok(Some(signed))
    }

    /// Reads one contiguous producer range, and refuses holes or mismatched sequences.
    pub fn records_between(
        &self,
        stream: &permguard_events::Stream,
        first: u64,
        last: u64,
    ) -> Result<Vec<Value>> {
        let scope = Scope::for_stream(stream);
        let expected = last.saturating_sub(first).saturating_add(1);
        let mut records = Vec::with_capacity(usize::try_from(expected).unwrap_or(0));
        for (segment, path) in self.segments(&scope)? {
            let segment_last = segment.saturating_add(SEGMENT_RECORDS.saturating_sub(1));
            if segment_last < first || segment > last {
                continue;
            }
            let start = first.max(segment);
            let end = last.min(segment_last);
            let count = end.saturating_sub(start).saturating_add(1);
            let (held, _) = read_segment(
                &path,
                start.saturating_sub(segment),
                usize::try_from(count).unwrap_or(usize::MAX),
            )?;
            records.extend(held);
        }
        if records.len() as u64 != expected {
            anyhow::bail!(
                "the producer range {first}..={last} contains {} records instead of {expected}",
                records.len()
            );
        }
        for (offset, record) in records.iter().enumerate() {
            let expected_sequence = first.saturating_add(offset as u64);
            if record.get("seq").and_then(Value::as_u64) != Some(expected_sequence) {
                anyhow::bail!(
                    "the producer range {first}..={last} has no record at sequence \
                     {expected_sequence}"
                );
            }
        }

        Ok(records)
    }

    /// Archives the public key a batch was signed under, the first time it is seen.
    ///
    /// A batch signed today must still verify after that key has been rotated a dozen times, and
    /// the producer's published set only carries what is current. Public material only: nothing
    /// this store holds could sign anything.
    pub fn archive_key(&self, key: &Jwk) -> Result<()> {
        let rendered = serde_json::to_vec(key).context("rendering a verification key")?;
        let fingerprint = permguard_events::record::digest_hex(&rendered);
        let path = self
            .root
            .join(KEYS_DIRECTORY)
            .join(format!("{}-{fingerprint}.json", safe(&key.kid)?));
        // A key id is a producer-local label, not a digest and not a globally unique name. The
        // content fingerprint makes two producers reusing one label two archive entries, while
        // the exact same key remains idempotent.
        if path.exists() {
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let held: Jwk = serde_json::from_slice(&bytes)
                .with_context(|| format!("reading the archived key {}", path.display()))?;
            if held == *key {
                return Ok(());
            }

            anyhow::bail!(
                "the verification-key archive path {} does not contain the material its content fingerprint names",
                path.display()
            );
        }
        let bytes = serde_json::to_vec_pretty(key).context("rendering a verification key")?;
        write_atomic(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;

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
            let committed = entry.file_type().is_ok_and(|kind| kind.is_file())
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'));
            if !committed {
                continue;
            }
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
        let producer = self.stream_path(stream)?;
        if producer.exists() {
            for (first, path) in segments_in(&producer)? {
                if first > acked {
                    dropped += lines_in(&path)?;
                    fs::remove_file(&path).context("removing an unacknowledged segment")?;
                } else {
                    dropped += truncate_above(&path, acked)?;
                }
            }
            rebuild_index(&producer)?;
        }

        let view = self.view_path(&stream.zone, &stream.ledger)?;
        if view.exists() {
            let previous = read_view_state(&view, &self.root)?;
            for (_, path) in segments_in(&view)? {
                dropped += truncate_stream_above(&path, stream, acked)?;
            }
            rebuild_index(&view)?;
            let mut rebuilt = rebuild_view_state(&view, &self.root)?;
            rebuilt.committed = previous.committed;
            // The frontier advances only at acknowledgement. Rebuilding it from physical rows
            // would make a crash-written, unacknowledged row visible as durable history.
            rebuilt.frontier = previous.frontier;
            write_view_state(&view, &rebuilt)?;
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

        // Once the producer state is durable, this is an acknowledged stream. Keep the derived
        // request index in step with that exact commit point; tenant-view recovery can repair its
        // own derived state independently if the remainder of this function is interrupted.
        let mut index = match self.stream_index.write() {
            Ok(index) => index,
            Err(poisoned) => poisoned.into_inner(),
        };
        index
            .entry((stream.zone.clone(), stream.ledger.clone()))
            .or_default()
            .insert((
                stream.producer.class.clone(),
                stream.producer.id.clone(),
                stream.producer.instance.clone(),
            ));
        drop(index);

        let view = self.view_path(&stream.zone, &stream.ledger)?;
        // The current ingest deliberately left an uncommitted suffix in this view. Reading the
        // raw state here avoids treating that ordinary in-flight suffix as crash debris and
        // scanning the whole view on every batch. Every other caller uses the recovering read.
        let mut view_state = read_view_state_raw(&view, &self.root)?;
        view_state
            .frontier
            .cover(&Scope::for_stream(stream).key(), acked.saturating_add(1));
        view_state.committed = view_state.next.saturating_sub(1);
        write_view_state(&view, &view_state)?;
        flush_tree(&view)?;

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
        write_atomic(&directory.join(STATE_FILE), &bytes).context("committing a stream's state")
    }

    /// The segments of one scope, oldest first.
    pub fn segments(&self, scope: &Scope) -> Result<Vec<(u64, PathBuf)>> {
        segments_in(&self.scope_path(scope)?)
    }

    /// The producer frontier at the durable end of a scope.
    pub fn frontier(&self, scope: &Scope) -> Result<Frontier> {
        match scope {
            Scope::Stream { .. } => {
                let stream = scope
                    .as_stream()
                    .ok_or_else(|| anyhow!("not a stream scope"))?;
                let state = self.stream_state(&stream)?;

                Ok(Frontier::of(&scope.key(), state.acked))
            }
            Scope::Tenant { zone, ledger } => {
                let directory = self.view_path(zone, ledger)?;

                let state = read_view_state(&directory, &self.root)?;
                let mut frontier = state.frontier;
                frontier.cover(&scope.key(), state.committed);

                Ok(frontier)
            }
        }
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
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(error) => {
                return Err(error).with_context(|| format!("listing {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", directory.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(slug) = name.strip_suffix(".idx") else {
                continue;
            };
            let held = unslug(slug).ok_or_else(|| {
                anyhow!(
                    "the event-type index file `{}` has no reversible registered type name",
                    entry.path().display()
                )
            })?;
            found.push(held);
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

/// Truncates the one suffix a process crash may leave: bytes after the last newline.
///
/// A complete line that is not JSON is corruption and stops the store. Only a final line without
/// its newline can be identified unambiguously as an interrupted append; treating any parse error
/// as torn would let durable evidence disappear under the name of recovery.
fn recover_torn_segments(root: &Path) -> Result<()> {
    let mut pending = vec![root.join("streams"), root.join("views")];
    let mut changed = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("listing {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", directory.display()))?;
            let kind = entry
                .file_type()
                .with_context(|| format!("reading the type of {}", entry.path().display()))?;
            if kind.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !kind.is_file()
                || entry.path().extension().and_then(|held| held.to_str()) != Some("events")
            {
                continue;
            }
            if recover_torn_segment(&entry.path())? {
                changed.insert(directory.clone());
            }
        }
    }

    for directory in changed {
        rebuild_index(&directory)?;
    }

    Ok(())
}

/// Recovers one append-only segment and reports whether it was truncated.
fn recover_torn_segment(path: &Path) -> Result<bool> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let complete = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |position| position.saturating_add(1));
    for (number, line) in bytes[..complete]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        serde_json::from_slice::<Value>(line).with_context(|| {
            format!(
                "reading complete record {} of {}",
                number.saturating_add(1),
                path.display()
            )
        })?;
    }
    if complete == bytes.len() {
        return Ok(false);
    }

    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {} for crash recovery", path.display()))?;
    file.set_len(complete as u64)
        .with_context(|| format!("truncating a torn record from {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing recovered segment {}", path.display()))?;
    if let Some(directory) = path.parent() {
        sync_directory(directory)?;
    }

    Ok(true)
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

/// Rebuilds the request-time stream index from acknowledged state.
///
/// Directories without `STATE` are unacknowledged crash debris and deliberately do not become
/// discoverable streams. A malformed committed state fails startup rather than silently hiding
/// evidence from pagination.
fn discover_streams(root: &Path) -> Result<StreamIndex> {
    fn directories(path: &Path) -> Result<Vec<(String, PathBuf)>> {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| format!("listing {}", path.display()));
            }
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", path.display()))?;
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            if let Ok(name) = entry.file_name().into_string() {
                names.push((name, entry.path()));
            }
        }

        Ok(names)
    }

    let mut found = BTreeMap::new();
    for (zone, zone_path) in directories(&root.join("streams"))? {
        for (ledger, ledger_path) in directories(&zone_path)? {
            for (class, class_path) in directories(&ledger_path)? {
                for (producer, producer_path) in directories(&class_path)? {
                    for (instance, instance_path) in directories(&producer_path)? {
                        let state_path = instance_path.join(STATE_FILE);
                        let bytes = match fs::read(&state_path) {
                            Ok(bytes) => bytes,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(error) => {
                                return Err(error)
                                    .with_context(|| format!("reading {}", state_path.display()));
                            }
                        };
                        let state: StreamState = serde_json::from_slice(&bytes)
                            .with_context(|| format!("reading {}", state_path.display()))?;
                        if state.acked == 0 {
                            continue;
                        }
                        found
                            .entry((zone.clone(), ledger.clone()))
                            .or_insert_with(BTreeSet::new)
                            .insert((class.clone(), producer.clone(), instance));
                    }
                }
            }
        }
    }

    Ok(found)
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

fn line_in_segment(position: u64) -> u64 {
    position.saturating_sub(1) % SEGMENT_RECORDS
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

fn read_view_state(directory: &Path, root: &Path) -> Result<ViewState> {
    let state = read_view_state_raw(directory, root)?;
    if state.committed < state.next.saturating_sub(1) {
        // This is only a recovery path. In the ordinary append/ack sequence there is no visible
        // suffix once the tenant gate is released. A suffix here means a process stopped between
        // the producer ACK and the tenant-view commit (now acknowledged), or before both (scratch).
        return recover_view(directory, root);
    }

    Ok(state)
}

fn read_view_state_raw(directory: &Path, root: &Path) -> Result<ViewState> {
    let path = directory.join(VIEW_STATE_FILE);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("reading the tenant view state {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            rebuild_view_state(directory, root)
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_view_state(directory: &Path, state: &ViewState) -> Result<()> {
    fs::create_dir_all(directory).context("creating a tenant view")?;
    let bytes = serde_json::to_vec_pretty(state).context("rendering a tenant view state")?;
    write_atomic(&directory.join(VIEW_STATE_FILE), &bytes).context("committing a tenant view state")
}

/// Repairs every derived tenant view before this process accepts work.
fn recover_views(root: &Path) -> Result<()> {
    let views = root.join("views");
    for zone in fs::read_dir(&views).with_context(|| format!("listing {}", views.display()))? {
        let zone = zone.context("listing event zones")?;
        if !zone.file_type().context("reading an event zone")?.is_dir() {
            continue;
        }
        for ledger in fs::read_dir(zone.path()).context("listing event ledgers")? {
            let ledger = ledger.context("listing event ledgers")?;
            if ledger
                .file_type()
                .context("reading an event ledger")?
                .is_dir()
            {
                recover_view(&ledger.path(), root)?;
            }
        }
    }

    Ok(())
}

/// Reconciles a tenant view with the authoritative ACK of every producer stream.
fn recover_view(directory: &Path, root: &Path) -> Result<ViewState> {
    let mut rebuilt = rebuild_view_state(directory, root)?;
    if rebuilt.committed < rebuilt.next.saturating_sub(1) {
        // An unacknowledged tenant-view row is scratch: the producer still owns it and will resend.
        // It is necessarily a suffix because one tenant gate spans append through acknowledgement.
        truncate_view_after(directory, rebuilt.committed)?;
        rebuild_index(directory)?;
        rebuilt = rebuild_view_state(directory, root)?;
    }
    write_view_state(directory, &rebuilt)?;

    Ok(rebuilt)
}

/// Removes the physical suffix after the last producer-acknowledged tenant position.
///
/// Tenant positions are append-only and contiguous within their numbered segments. Retention may
/// have removed older whole segments, but it never renumbers what remains, so the segment's first
/// position plus its line number is still the authoritative position.
fn truncate_view_after(directory: &Path, committed: u64) -> Result<()> {
    let mut changed = false;
    for (first, path) in segments_in(directory)? {
        if first > committed {
            fs::remove_file(&path).with_context(|| {
                format!("removing uncommitted tenant segment {}", path.display())
            })?;
            changed = true;
            continue;
        }

        let Some(text) = read_or_absent(&path)? else {
            continue;
        };
        let keep = usize::try_from(committed.saturating_sub(first).saturating_add(1))
            .unwrap_or(usize::MAX);
        let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
        if keep >= lines.len() {
            continue;
        }

        if keep == 0 {
            fs::remove_file(&path).with_context(|| {
                format!("removing uncommitted tenant segment {}", path.display())
            })?;
        } else {
            let mut retained = lines[..keep].join("\n");
            retained.push('\n');
            write_atomic(&path, retained.as_bytes())
                .with_context(|| format!("truncating tenant segment {}", path.display()))?;
        }
        changed = true;
    }
    if changed {
        sync_directory(directory)?;
    }

    Ok(())
}

/// Re-derives the merged view's append position and per-producer frontier from its authoritative
/// records. Used after rollback and when a derived state file is lost.
fn rebuild_view_state(directory: &Path, root: &Path) -> Result<ViewState> {
    let mut state = ViewState::default();
    let mut acknowledged: BTreeMap<String, u64> = BTreeMap::new();
    let mut durable_prefix = true;
    for (first, path) in segments_in(directory)? {
        let Some(text) = read_or_absent(&path)? else {
            continue;
        };
        for (number, line) in text.lines().filter(|line| !line.is_empty()).enumerate() {
            let record: Value = serde_json::from_str(line)
                .with_context(|| format!("reading record {} of {}", number + 1, path.display()))?;
            let stream: permguard_events::Stream = serde_json::from_value(
                record
                    .get("stream")
                    .cloned()
                    .ok_or_else(|| anyhow!("a tenant-view record has no stream"))?,
            )
            .context("reading a tenant-view record's stream")?;
            let seq = record
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("a tenant-view record has no sequence"))?;
            let position = first.saturating_add(number as u64);
            state.next = state.next.max(position.saturating_add(1));

            if durable_prefix {
                let key = Scope::for_stream(&stream).key();
                let acked = match acknowledged.get(&key) {
                    Some(acked) => *acked,
                    None => {
                        let mut stream_directory = root.join("streams");
                        for segment in [
                            stream.zone.as_str(),
                            stream.ledger.as_str(),
                            stream.producer.class.as_str(),
                            stream.producer.id.as_str(),
                            stream.producer.instance.as_str(),
                        ] {
                            stream_directory.push(safe(segment)?);
                        }
                        let state_path = stream_directory.join(STATE_FILE);
                        let acked = match fs::read(&state_path) {
                            Ok(bytes) => {
                                serde_json::from_slice::<StreamState>(&bytes)
                                    .with_context(|| {
                                        format!("reading stream state {}", state_path.display())
                                    })?
                                    .acked
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                            Err(error) => {
                                return Err(error)
                                    .with_context(|| format!("reading {}", state_path.display()));
                            }
                        };
                        acknowledged.insert(key.clone(), acked);
                        acked
                    }
                };
                if seq <= acked {
                    state.committed = position;
                    state.frontier.cover(&key, seq.saturating_add(1));
                } else {
                    // Ingest holds the tenant gate from append through acknowledgement, so an
                    // unacknowledged row can only be a suffix left by a crash. No later position
                    // may be published around that hole.
                    durable_prefix = false;
                }
            }
        }
    }

    Ok(state)
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
        let first = rest.parse::<u64>().with_context(|| {
            format!(
                "the event segment {} has a non-numeric first position",
                entry.path().display()
            )
        })?;
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
fn append_line(path: &Path, line_number: u64, line: &str) -> Result<(u64, u64)> {
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
        .ok_or_else(|| anyhow!("{} is not a numbered event segment", path.display()))?;

    Ok((first, line_number))
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
    for (number, line) in text.lines().filter(|line| !line.is_empty()).enumerate() {
        let record: Value = serde_json::from_str(line)
            .with_context(|| format!("reading record {} of {}", number + 1, path.display()))?;
        let seq = record.get("seq").and_then(Value::as_u64).ok_or_else(|| {
            anyhow!(
                "record {} of {} has no sequence",
                number + 1,
                path.display()
            )
        })?;
        if seq > acked {
            dropped += 1;
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    if dropped > 0 {
        write_atomic(path, kept.as_bytes()).context("truncating a segment")?;
    }

    Ok(dropped)
}

/// Drops only one producer's unacknowledged records from a merged view.
fn truncate_stream_above(
    path: &Path,
    stream: &permguard_events::Stream,
    acked: u64,
) -> Result<u64> {
    let Some(text) = read_or_absent(path)? else {
        return Ok(0);
    };
    let mut kept = String::new();
    let mut dropped = 0;
    for (number, line) in text.lines().filter(|line| !line.is_empty()).enumerate() {
        let record: Value = serde_json::from_str(line)
            .with_context(|| format!("reading record {} of {}", number + 1, path.display()))?;
        let held_stream = record
            .get("stream")
            .cloned()
            .ok_or_else(|| anyhow!("record {} of {} has no stream", number + 1, path.display()))?;
        let held_stream: permguard_events::Stream = serde_json::from_value(held_stream)
            .with_context(|| format!("reading stream {} of {}", number + 1, path.display()))?;
        let same_stream = held_stream == *stream;
        let sequence = record.get("seq").and_then(Value::as_u64).ok_or_else(|| {
            anyhow!(
                "record {} of {} has no sequence",
                number + 1,
                path.display()
            )
        })?;
        if same_stream && sequence > acked {
            dropped += 1;
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    if dropped > 0 {
        write_atomic(path, kept.as_bytes()).context("truncating a tenant view")?;
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
/// them. Dots and slashes keep the spelling used by the original on-disk format; bytes that would
/// collide with those spellings are percent-encoded. Thus `a.b`, `a-b`, `a/b` and `a_b` are four
/// different indexes rather than two pairs sharing files.
fn slug(event_type: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(event_type.len());
    for byte in event_type.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => encoded.push(char::from(byte)),
            b'.' => encoded.push('-'),
            b'/' => encoded.push('_'),
            _ => {
                encoded.push('%');
                encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }

    encoded
}

fn unslug(slug: &str) -> Option<String> {
    if slug.is_empty() {
        return None;
    }
    let bytes = slug.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while at < bytes.len() {
        match bytes[at] {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => decoded.push(bytes[at]),
            b'-' => decoded.push(b'.'),
            b'_' => decoded.push(b'/'),
            b'%' => {
                let high = hex_value(*bytes.get(at.saturating_add(1))?)?;
                let low = hex_value(*bytes.get(at.saturating_add(2))?)?;
                decoded.push((high << 4) | low);
                at = at.saturating_add(2);
            }
            _ => return None,
        }
        at = at.saturating_add(1);
    }

    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
    match fs::remove_dir_all(&index) {
        Ok(()) => sync_directory(directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("removing {}", index.display()));
        }
    }
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
            let event_type = record
                .get("event_type")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow!(
                        "the record at line {} of {} has no event type",
                        line_number + 1,
                        path.display()
                    )
                })?;
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
    sync_directory(directory)?;
    for (event_type, held) in positions {
        let body: String = held
            .into_iter()
            .map(|(segment, line)| format!("{segment}:{line}\n"))
            .collect();
        write_atomic(&index_path(directory, &event_type), body.as_bytes())
            .context("writing an index")?;
    }

    Ok(())
}

/// Atomically replaces one file and makes both its bytes and its directory entry durable.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("{} has no portable file name", path.display()))?;
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temporary = parent.join(format!(
        ".{name}.writing-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("opening {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))?;
    sync_directory(parent)
}

pub(crate) fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .with_context(|| format!("opening directory {}", directory.display()))?
        .sync_all()
        .with_context(|| format!("flushing directory {}", directory.display()))
}

/// `fsync`s every file of a directory, and the directory itself.
fn flush_tree(directory: &Path) -> Result<()> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("listing {} before flushing it", directory.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("listing {}", directory.display()))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .with_context(|| format!("reading the type of {}", path.display()))?;
        if kind.is_dir() {
            flush_tree(&path)?;
            continue;
        }
        if kind.is_file() {
            fs::File::open(&path)
                .with_context(|| format!("opening {} before flushing it", path.display()))?
                .sync_all()
                .with_context(|| format!("flushing {}", path.display()))?;
        }
    }
    // A directory `fsync` is what makes a *newly created* file survive: the file's own flush does
    // not persist the entry that names it.
    sync_directory(directory)?;

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
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
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

#[cfg(test)]
mod tests {
    use super::{slug, unslug};

    #[test]
    fn event_type_file_names_are_reversible_and_collision_free() {
        let types = [
            "permguard.dogwood.event.v1",
            "vendor.event-type.v1",
            "vendor/event_type/v1",
            "événement.一.v1",
        ];
        let slugs: std::collections::BTreeSet<String> =
            types.iter().map(|event_type| slug(event_type)).collect();
        assert_eq!(slugs.len(), types.len());
        for event_type in types {
            assert_eq!(unslug(&slug(event_type)).as_deref(), Some(event_type));
        }
        assert_ne!(slug("a.b"), slug("a-b"));
        assert_ne!(slug("a/b"), slug("a_b"));
    }

    #[test]
    fn malformed_event_type_file_names_are_not_invented_into_types() {
        for malformed in ["", "%", "%0", "%GG", "raw:colon"] {
            assert_eq!(unslug(malformed), None, "{malformed}");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn the_stream_walk_is_paged_filtered_and_cut_at_the_directory() {
        let root = std::env::temp_dir().join(format!("stream-page-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        // Five acknowledged incarnations across two producers of one class. The request-time
        // index is rebuilt from these durable states when the store opens.
        for (id, instance) in [
            ("plane-a", "i1"),
            ("plane-a", "i2"),
            ("plane-a", "i3"),
            ("plane-b", "i1"),
            ("plane-b", "i2"),
        ] {
            let directory = root
                .join("streams")
                .join("acme")
                .join("main")
                .join("data-plane")
                .join(id)
                .join(instance);
            std::fs::create_dir_all(&directory).expect("the stream directory is created");
            std::fs::write(
                directory.join(super::STATE_FILE),
                br#"{"acked":1,"head":"held"}"#,
            )
            .expect("the state is written");
        }
        let store = super::EventStore::open(&root).expect("the store opens");

        // A page smaller than the whole: cut, truthful about it, resumable from the last triple.
        let first = store
            .producer_streams_page("acme", "main", None, None, None, None, 2)
            .expect("the first page walks");
        assert_eq!(first.streams.len(), 2);
        assert!(first.truncated);
        let last = &first.streams[1].producer;
        let second = store
            .producer_streams_page(
                "acme",
                "main",
                None,
                None,
                None,
                Some(("data-plane", last.id.as_str(), last.instance.as_str())),
                2,
            )
            .expect("the second page walks");
        assert_eq!(second.streams.len(), 2);
        assert!(second.truncated);
        let third = store
            .producer_streams_page(
                "acme",
                "main",
                None,
                None,
                None,
                Some((
                    "data-plane",
                    second.streams[1].producer.id.as_str(),
                    second.streams[1].producer.instance.as_str(),
                )),
                2,
            )
            .expect("the last page walks");
        assert_eq!(third.streams.len(), 1);
        assert!(!third.truncated, "the last page says it is the last");

        // Pages tile: every incarnation exactly once, in order.
        let mut walked: Vec<(String, String)> = Vec::new();
        for page in [&first, &second, &third] {
            walked.extend(
                page.streams
                    .iter()
                    .map(|held| (held.producer.id.clone(), held.producer.instance.clone())),
            );
        }
        assert_eq!(
            walked,
            [
                ("plane-a", "i1"),
                ("plane-a", "i2"),
                ("plane-a", "i3"),
                ("plane-b", "i1"),
                ("plane-b", "i2"),
            ]
            .map(|(id, instance)| (id.to_owned(), instance.to_owned()))
        );

        // The filter cuts at the walk, and an unmatched one is empty rather than an error.
        let one = store
            .producer_streams_page("acme", "main", None, Some("plane-b"), None, None, 10)
            .expect("the filter walks");
        assert_eq!(one.streams.len(), 2);
        assert!(!one.truncated);
        assert!(one.streams.iter().all(|held| held.producer.id == "plane-b"));
        let nobody = store
            .producer_streams_page("acme", "main", None, Some("plane-x"), None, None, 10)
            .expect("an unmatched filter walks");
        assert!(nobody.streams.is_empty());

        std::fs::remove_dir_all(&root).ok();
    }
}
