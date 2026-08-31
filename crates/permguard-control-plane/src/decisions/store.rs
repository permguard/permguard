// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where decision records are kept: verbatim, append-only, and indexed into
//! per-tenant views.
//!
//! # The layout
//!
//! ```text
//! <volume>/data/decisions/store/
//!   streams/<pdp-id>/<instance>/
//!       STATE                        acked, head digest, whether it is closed
//!       EPOCHS.jsonl                 every marker and discontinuity of this stream
//!       seg-<first>.jsonl            the records, exactly as they were signed
//!       batch-<first>.jws            the envelope that attested them
//!   views/<zone>/<ledger>/
//!       seg-<first>.jsonl            the same records, for one tenant
//!   verification-keys/<kid>.json     the PUBLIC halves that attest the segments
//! ```
//!
//! Under `data/` because that is what a restore has to bring back, beside the
//! ledgers rather than at the volume root. And **not** under `operations/keys`,
//! because none of this is a ring: `verification-keys` holds the public half of
//! somebody else's ring, copied in as evidence beside what it attests.
//!
//! # Verbatim, and why it is not negotiable
//!
//! The producer chain is `prev(N) = digest(N − 1)` over the bytes the producer
//! signed. A store that reparsed a record into a struct it understands and
//! re-serialised it would drop any field a newer producer added, and every
//! digest after that record would stop matching. So records are held as they
//! arrived, byte for byte, and this module never looks inside one except to
//! read the few fields it must index by.
//!
//! # Views are partitions, not filters
//!
//! `store.zone` and `store.ledger` are inside the record, covered by its
//! digest and by the batch signature, so the demultiplexing cannot be steered
//! by anything a caller can change. A tenant then reads a directory that
//! physically contains only its own records — a bug in a predicate leaks
//! another tenant's data, a partition cannot.
//!
//! # Stream-level records live in every view
//!
//! `marker` and `discontinuity` records carry no tenancy: they are properties
//! of the producer. A view that did not contain them would hold records whose
//! completeness claim — the sampling rate, the build, the fact that the stream
//! ended — is stated in a record the tenant cannot read. So they are copied
//! into every view of their stream, and a view opened later is back-filled
//! from `EPOCHS.jsonl` before it takes its first record.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow, bail};
use permguard_core::Jwk;
use permguard_decisions::record::GENESIS;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const STATE_FILE: &str = "STATE";
/// Where the *public* halves that attest the segments are archived.
///
/// Deliberately not `keys`: a directory called that beside a server's data is
/// read as key material, and this holds none — see [`DecisionStore::archive_key`].
const KEYS_DIRECTORY: &str = "verification-keys";
const EPOCHS_FILE: &str = "EPOCHS.jsonl";
const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".jsonl";

/// How much one segment holds before the next is started.
///
/// Segments are the unit of sealing, of retention and of the opaque offset, so
/// they are sized for a file an operator can still open by hand.
const SEGMENT_BYTES: u64 = 32 * 1024 * 1024;

/// What the store knows about one producer stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamState {
    /// The highest **contiguous durable** sequence. Never the highest accepted.
    pub acked: u64,
    /// The digest at that point, which the next record must name.
    pub head: String,
    /// Set when the stream was closed permanently, and why.
    ///
    /// A closed stream never accepts another record. What is already stored
    /// stays exactly as it is, as evidence: repairing history would be
    /// indistinguishable, to a later auditor, from an attacker doing the same.
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

/// The gate one stream's writer holds, and the map they are handed out from.
type StreamGate = Arc<std::sync::Mutex<()>>;
type StreamGates = std::sync::Mutex<std::collections::HashMap<(String, String), StreamGate>>;

/// The append-only store of decision records.
pub struct DecisionStore {
    root: PathBuf,
    /// One gate per stream, handed to whoever is about to write it.
    ///
    /// Ingest is read-check-append across several files, and two batches for
    /// one stream interleaving that sequence would corrupt exactly what this
    /// store exists to keep whole. A well-behaved shipper is sequential; the
    /// gate is for the day something else is not. Streams stay independent —
    /// one slow producer does not queue another's batches.
    gates: StreamGates,
}

impl DecisionStore {
    /// Opens the store rooted at `directory`.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let root = directory.into();
        fs::create_dir_all(root.join("streams")).context("creating the decision store")?;
        fs::create_dir_all(root.join("views")).context("creating the decision store")?;
        fs::create_dir_all(root.join(KEYS_DIRECTORY)).context("creating the decision store")?;

        Ok(Self {
            root,
            gates: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The write gate of one stream. Held for the whole of an ingest.
    pub fn gate(&self, pdp_id: &str, instance: &str) -> StreamGate {
        let mut gates = match self.gates.lock() {
            Ok(gates) => gates,
            Err(poisoned) => poisoned.into_inner(),
        };

        Arc::clone(
            gates
                .entry((pdp_id.to_owned(), instance.to_owned()))
                .or_default(),
        )
    }

    /// Where the store lives.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// What is known about one stream. A stream nobody has shipped is fresh.
    pub fn stream_state(&self, pdp_id: &str, instance: &str) -> Result<StreamState> {
        let path = self.stream_path(pdp_id, instance)?.join(STATE_FILE);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("reading a stream's state"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(StreamState::fresh()),
            Err(error) => Err(error).context("reading a stream's state"),
        }
    }

    /// Appends one record and, when it belongs to a tenant, to that tenant's view.
    ///
    /// Nothing here is acknowledged: durability is a separate, explicit step,
    /// because the producer is about to delete its only other copy on the
    /// strength of it.
    pub fn append(&self, pdp_id: &str, instance: &str, record: &Value) -> Result<()> {
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("a record with no `seq`"))?;
        let stream = self.stream_path(pdp_id, instance)?;
        fs::create_dir_all(&stream).context("creating a stream directory")?;

        let line = render(record)?;
        append_line(&segment_for(&stream, seq)?, &line)?;

        match tenancy(record) {
            Some((zone, ledger)) => {
                let view = self.view_path(&zone, &ledger)?;
                self.ensure_view(&view, &stream)?;
                self.remember_view(&stream, &zone, &ledger)?;
                append_line(&segment_for(&view, seq)?, &line)?;
            }
            None => {
                // A property of the producer: it belongs to every view of this
                // stream, and to every view opened for it afterwards.
                append_line(&stream.join(EPOCHS_FILE), &line)?;
                for view in self.views_of(&stream)? {
                    append_line(&segment_for(&view, seq)?, &line)?;
                }
            }
        }

        Ok(())
    }

    /// Discards the records physically present above `acked`, everywhere they
    /// were written.
    ///
    /// # Why an unacknowledged record is not history
    ///
    /// [`Self::append`] writes before [`Self::acknowledge`] flushes and moves
    /// the acknowledged point, so a crash in between leaves records on disk
    /// that the producer was never told about. The producer still holds them —
    /// that is what its spool is for — and it resends them. What it resends is
    /// **not obliged to be the same bytes**: a producer that came under
    /// pressure in the meantime ends its stream and its next record at
    /// `acked + 1` is a terminal record instead of the decision that was there
    /// before.
    ///
    /// So the physical tail above `acked` is scratch, and it is discarded
    /// before a batch that advances the stream is appended. Without that, the
    /// two outcomes are a second line at a sequence the store already holds —
    /// which is not a chain any reader can verify — or a spurious
    /// [`Refused::Conflict`](super::ingest::Refused::Conflict) that closes a
    /// healthy stream permanently.
    ///
    /// Only records **at or below** `acked` are immutable, and those this never
    /// touches.
    pub fn rollback_unacked(&self, pdp_id: &str, instance: &str, acked: u64) -> Result<u64> {
        let stream = self.stream_path(pdp_id, instance)?;
        if !stream.exists() {
            return Ok(0);
        }
        let mut dropped = 0;
        let mut scopes = vec![stream.clone()];
        scopes.extend(self.views_of(&stream)?);
        for scope in scopes {
            for (first, path) in segments_in(&scope)? {
                if first > acked {
                    dropped += lines_in(&path)?;
                    fs::remove_file(&path).context("removing an unacknowledged segment")?;
                    continue;
                }
                dropped += truncate_above(&path, acked)?;
            }
        }
        // The epoch index is appended before the acknowledgement too, so an
        // unacknowledged marker is scratch there as well — otherwise a view
        // opened later is back-filled from a record nobody stored.
        dropped += truncate_above(&stream.join(EPOCHS_FILE), acked)?;

        Ok(dropped)
    }

    /// Records that everything up to `acked` is durable, and flushes it.
    ///
    /// "Durable" is defined, not implied: the records and the index entries
    /// that make them findable are written **and flushed**, such that a
    /// process restart or a host restart finds them.
    pub fn acknowledge(
        &self,
        pdp_id: &str,
        instance: &str,
        acked: u64,
        head: &str,
    ) -> Result<StreamState> {
        let stream = self.stream_path(pdp_id, instance)?;
        flush_tree(&stream)?;
        for view in self.views_of(&stream)? {
            flush_tree(&view)?;
        }

        let mut state = self.stream_state(pdp_id, instance)?;
        state.acked = acked;
        state.head = head.to_owned();
        self.write_state(&stream, &state)?;

        Ok(state)
    }

    /// Closes a stream permanently, and says why.
    pub fn close(&self, pdp_id: &str, instance: &str, reason: &str) -> Result<()> {
        let stream = self.stream_path(pdp_id, instance)?;
        fs::create_dir_all(&stream).context("creating a stream directory")?;
        let mut state = self.stream_state(pdp_id, instance)?;
        state.closed = Some(reason.to_owned());

        self.write_state(&stream, &state)
    }

    /// Keeps the envelope that attested a batch, beside the records it covers.
    ///
    /// The signature is the evidence: without it a verifier holds records and
    /// a chain, and no way to attribute either.
    pub fn keep_envelope(
        &self,
        pdp_id: &str,
        instance: &str,
        first_seq: u64,
        signed: &Value,
    ) -> Result<()> {
        let stream = self.stream_path(pdp_id, instance)?;
        fs::create_dir_all(&stream).context("creating a stream directory")?;
        let path = stream.join(format!("batch-{first_seq:020}.jws"));
        let bytes = serde_json::to_vec(signed).context("describing a signature")?;
        write_durable(&path, &bytes)
    }

    /// Records which key verified the batch starting at `first_seq`, beside the stream.
    ///
    /// [`archive_key`](Self::archive_key) keeps every key ever seen; this keeps *which stretch*
    /// each one covers — the offset-ranged answer a verifier needs to check a slice of stream
    /// without downloading every key the producer ever held.
    pub fn note_signer(
        &self,
        pdp_id: &str,
        instance: &str,
        first_seq: u64,
        key: &Jwk,
    ) -> Result<()> {
        let stream = self.stream_path(pdp_id, instance)?;
        fs::create_dir_all(&stream).context("creating a stream directory")?;
        let path = stream.join(permguard_stream::SIGNERS_FILE);
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
    /// Called under the stream gate before any evidence is replaced, so a reused `kid` with
    /// different material cannot be discovered only after the old envelope has gone.
    pub fn check_signer(
        &self,
        pdp_id: &str,
        instance: &str,
        first_seq: u64,
        key: &Jwk,
    ) -> Result<()> {
        let path = self
            .stream_path(pdp_id, instance)?
            .join(permguard_stream::SIGNERS_FILE);
        let signers =
            permguard_stream::Signers::load(&path).context("reading the signer manifest")?;
        let jwk = serde_json::to_value(key).context("rendering a signer key")?;
        signers
            .check_observation(first_seq, &key.kid, &jwk)
            .map_err(|error| anyhow::anyhow!("recording a signer: {error}"))
    }

    /// Whether this store holds anything at all for one producer stream.
    ///
    /// Existence is the directory's: a stream that never shipped a batch has no directory, and
    /// answering questions about it with empty defaults would dress a typo as a quiet stream.
    pub fn stream_exists(&self, pdp_id: &str, instance: &str) -> Result<bool> {
        Ok(self.stream_path(pdp_id, instance)?.is_dir())
    }

    /// Which key signed which stretch of one stream, as this store verified it.
    pub fn signers(&self, pdp_id: &str, instance: &str) -> Result<permguard_stream::Signers> {
        let path = self
            .stream_path(pdp_id, instance)?
            .join(permguard_stream::SIGNERS_FILE);

        permguard_stream::Signers::load(&path).context("reading the signer manifest")
    }

    /// Archives a verification key beside what it attests.
    ///
    /// A batch signed today must still verify years from now, after the key has
    /// been rotated a dozen times. Deleting a public key because it is no
    /// longer in use would destroy the ability to verify the past, which is the
    /// one thing an audit store exists for.
    ///
    /// **This is not a key ring, and the directory is named so that nobody has
    /// to check.** A ring holds private halves, rotates them and lives under
    /// `operations/keys` with the server's other rings. What is kept here is
    /// the *public* half of somebody else's ring, copied in as evidence,
    /// alongside the records it attests — so an exported segment stays
    /// checkable by whoever holds it, without this plane's key material going
    /// anywhere near it.
    pub fn archive_key(&self, key: &Jwk) -> Result<()> {
        let name = safe(&key.kid).ok_or_else(|| anyhow!("a key id that is not a name"))?;
        let rendered = serde_json::to_vec(key).context("describing a verification key")?;
        // The content fingerprint is part of the name, exactly as the event archive does it: a
        // `kid` is a producer-local label, not a global identifier, and two producers reusing one
        // label are two archive entries rather than the second being refused as a substitution.
        // (Per-stream substitution — one stream, one name, two keys — is the signer manifest's
        // refusal, where the scope is right.)
        let fingerprint = fingerprint_hex(&rendered);
        let path = self
            .root
            .join(KEYS_DIRECTORY)
            .join(format!("{name}-{fingerprint}.json"));
        // An existing file is still read, never trusted by its name: a file that mismatches its
        // own fingerprint or no longer parses is evidence this archive cannot stand behind, and
        // it fails closed rather than shrugging.
        match fs::read(&path) {
            Ok(bytes) => {
                let held: Jwk = serde_json::from_slice(&bytes).with_context(|| {
                    format!("the archived key {} no longer parses", path.display())
                })?;
                if &held != key {
                    bail!(
                        "the archived key {} does not match the material its name claims",
                        path.display()
                    );
                }

                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_durable(&path, &rendered)
            }
            Err(error) => {
                Err(error).with_context(|| format!("reading the archived key {}", path.display()))
            }
        }
    }

    /// Every archived verification key.
    pub fn archived_keys(&self) -> Result<Vec<Jwk>> {
        let mut keys = Vec::new();
        let directory = self.root.join(KEYS_DIRECTORY);
        let Ok(entries) = fs::read_dir(&directory) else {
            return Ok(keys);
        };
        for entry in entries {
            let entry = entry.context("listing the archived keys")?;
            let path = entry.path();
            let committed = entry.file_type().is_ok_and(|kind| kind.is_file())
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json");
            if !committed {
                continue;
            }
            let bytes = fs::read(&path).context("reading an archived key")?;
            // Fail closed: an archived key that no longer parses is not one fewer key, it is an
            // archive that can no longer stand behind what it verified.
            let key: Jwk = serde_json::from_slice(&bytes)
                .with_context(|| format!("the archived key {} no longer parses", path.display()))?;
            keys.push(key);
        }

        Ok(keys)
    }

    /// The batch envelopes that attest a stream, oldest first.
    ///
    /// A reader that wants to check signatures needs these: the records carry
    /// the chain, and the envelope is what a key signed. Served rather than
    /// kept private because the whole point of the signature is that somebody
    /// else can check it.
    pub fn envelopes(&self, pdp_id: &str, instance: &str) -> Result<Vec<Value>> {
        let stream = self.stream_path(pdp_id, instance)?;
        let mut found: Vec<(String, Value)> = Vec::new();
        let Ok(entries) = fs::read_dir(&stream) else {
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

    /// The segments of one scope, oldest first.
    pub fn segments(&self, scope: &Scope) -> Result<Vec<(u64, PathBuf)>> {
        let directory = match scope {
            Scope::Stream { pdp_id, instance } => self.stream_path(pdp_id, instance)?,
            Scope::Tenant { zone, ledger } => self.view_path(zone, ledger)?,
        };

        segments_in(&directory)
    }

    fn ensure_view(&self, view: &Path, stream: &Path) -> Result<()> {
        if view.exists() {
            return Ok(());
        }
        fs::create_dir_all(view).context("creating a tenant view")?;
        // Back-fill the epochs, so the view is a self-describing stream from
        // its first record rather than a bag of rows.
        if let Ok(epochs) = fs::read_to_string(stream.join(EPOCHS_FILE)) {
            for line in epochs.lines() {
                if line.is_empty() {
                    continue;
                }
                let seq = serde_json::from_str::<Value>(line)
                    .ok()
                    .and_then(|value| value.get("seq").and_then(Value::as_u64))
                    .unwrap_or_default();
                append_line(&segment_for(view, seq)?, &format!("{line}\n"))?;
            }
        }

        Ok(())
    }

    fn views_of(&self, stream: &Path) -> Result<Vec<PathBuf>> {
        // Which tenants this stream has written to is answered by which views
        // hold any of its records. Kept as a file beside the stream rather than
        // walked, because walking every view on every marker would cost the
        // whole store per epoch.
        let path = stream.join("VIEWS");
        let Ok(text) = fs::read_to_string(&path) else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for line in text.lines() {
            if let Some((zone, ledger)) = line.split_once('\t') {
                found.push(self.view_path(zone, ledger)?);
            }
        }

        Ok(found)
    }

    fn remember_view(&self, stream: &Path, zone: &str, ledger: &str) -> Result<()> {
        let path = stream.join("VIEWS");
        let line = format!("{zone}\t{ledger}\n");
        if let Ok(text) = fs::read_to_string(&path)
            && text.lines().any(|held| held == line.trim_end())
        {
            return Ok(());
        }

        append_line(&path, &line)
    }

    fn write_state(&self, stream: &Path, state: &StreamState) -> Result<()> {
        let bytes = serde_json::to_vec(state).context("describing a stream's state")?;
        write_durable(&stream.join(STATE_FILE), &bytes)
    }

    fn stream_path(&self, pdp_id: &str, instance: &str) -> Result<PathBuf> {
        let pdp_id = safe(pdp_id).ok_or_else(|| anyhow!("`{pdp_id}` is not a producer name"))?;
        let instance =
            safe(instance).ok_or_else(|| anyhow!("`{instance}` is not an incarnation id"))?;

        Ok(self.root.join("streams").join(pdp_id).join(instance))
    }

    fn view_path(&self, zone: &str, ledger: &str) -> Result<PathBuf> {
        let zone = safe(zone).ok_or_else(|| anyhow!("`{zone}` is not a zone name"))?;
        let ledger = safe(ledger).ok_or_else(|| anyhow!("`{ledger}` is not a ledger name"))?;

        Ok(self.root.join("views").join(zone).join(ledger))
    }
}

/// Which records a reader is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// One producer's whole stream — the privileged, deployment-wide read.
    Stream {
        /// The producer.
        pdp_id: String,
        /// Which incarnation of it.
        instance: String,
    },
    /// One tenant's records.
    Tenant {
        /// The zone that owns them.
        zone: String,
        /// The ledger they were decided from.
        ledger: String,
    },
}

impl Scope {
    /// A stable name for this scope, which an offset is bound to.
    pub fn key(&self) -> String {
        match self {
            Self::Stream { pdp_id, instance } => format!("stream:{pdp_id}:{instance}"),
            Self::Tenant { zone, ledger } => format!("tenant:{zone}:{ledger}"),
        }
    }
}

/// The tenancy inside a record, when it has one.
pub fn tenancy(record: &Value) -> Option<(String, String)> {
    let store = record.get("store")?;
    let zone = store.get("zone")?.as_str()?.to_owned();
    let ledger = store.get("ledger")?.as_str()?.to_owned();

    Some((zone, ledger))
}

fn render(record: &Value) -> Result<String> {
    // `to_string` of the parsed value, which is what arrived: the canonical
    // form is what the digest is taken over, not what is stored, and storing
    // a re-canonicalised record would be a rewrite.
    let mut line = serde_json::to_string(record).context("describing a record")?;
    line.push('\n');

    Ok(line)
}

fn segments_in(directory: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(found);
    };
    for entry in entries {
        let entry = entry.context("listing a scope")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(first) = name
            .strip_prefix(SEGMENT_PREFIX)
            .and_then(|rest| rest.strip_suffix(SEGMENT_SUFFIX))
            .and_then(|digits| digits.parse::<u64>().ok())
        {
            found.push((first, entry.path()));
        }
    }
    found.sort_by_key(|(first, _)| *first);

    Ok(found)
}

fn segment_for(directory: &Path, seq: u64) -> Result<PathBuf> {
    let segments = segments_in(directory)?;
    match segments.last() {
        Some((_, path)) => {
            let full = fs::metadata(path).map(|meta| meta.len()).unwrap_or(0) >= SEGMENT_BYTES;
            if full {
                Ok(directory.join(format!("{SEGMENT_PREFIX}{seq:020}{SEGMENT_SUFFIX}")))
            } else {
                Ok(path.clone())
            }
        }
        None => Ok(directory.join(format!("{SEGMENT_PREFIX}{seq:020}{SEGMENT_SUFFIX}"))),
    }
}

fn append_line(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("creating a segment directory")?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("appending to {}", path.display()))?;
    file.write_all(line.as_bytes())
        .context("appending a record")?;

    Ok(())
}

/// How many records a segment holds.
fn lines_in(path: &Path) -> Result<u64> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).context("reading a segment"),
    };

    Ok(text.lines().filter(|line| !line.is_empty()).count() as u64)
}

/// Rewrites `path` without the records above `acked`, and returns how many left.
///
/// Durable, and it rewrites nothing when there was nothing to drop: the common
/// case is a store that crashed at no interesting moment at all.
fn truncate_above(path: &Path, acked: u64) -> Result<u64> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).context("reading a segment"),
    };
    let mut kept = String::with_capacity(text.len());
    let mut dropped = 0;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let seq = serde_json::from_str::<Value>(line)
            .context("reading a record")?
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("a stored record with no `seq`"))?;
        if seq > acked {
            dropped += 1;
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    if dropped == 0 {
        return Ok(0);
    }
    if kept.is_empty() {
        fs::remove_file(path).context("removing an unacknowledged segment")?;
    } else {
        write_durable(path, kept.as_bytes())?;
    }

    Ok(dropped)
}

/// The SHA-256 of `bytes`, hex, shortened to a filename-sized prefix — the same digest the event
/// archive names its entries with.
fn fingerprint_hex(bytes: &[u8]) -> String {
    let mut digest = permguard_events::record::digest_hex(bytes);
    digest.truncate(32);

    digest
}

fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("creating a directory")?;
    }
    // The staging name is unique per writer: streams hold their own gates, but two first-time
    // ingests under one key share this file's *target*, and a fixed `.next` would let one
    // writer's rename race the other's half-written staging into place.
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = format!(
        "next-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let temporary = path.with_extension(unique);
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .context("writing")?;
        file.write_all(bytes).context("writing")?;
        file.sync_all().context("flushing")?;
    }
    fs::rename(&temporary, path).context("replacing")?;
    if let Some(parent) = path.parent()
        && let Ok(handle) = File::open(parent)
    {
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Flushes every file of a directory tree, so a restart finds them.
fn flush_tree(directory: &Path) -> Result<()> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry.context("flushing a scope")?;
        if entry.path().is_file()
            && let Ok(file) = File::open(entry.path())
        {
            file.sync_all().context("flushing a segment")?;
        }
    }
    if let Ok(handle) = File::open(directory) {
        let _ = handle.sync_all();
    }

    Ok(())
}

/// Accepts a name that can be a directory, and nothing else.
///
/// A producer names its own stream and a record names its own zone, so both
/// reach this store from outside. A name carrying `..` or a separator would
/// place a segment wherever the sender chose.
fn safe(name: &str) -> Option<String> {
    permguard_stream::is_portable_name(name).then(|| name.to_owned())
}

/// Reads the records of `path` after `position`, up to `limit`.
pub fn read_segment(path: &Path, position: u64, limit: usize) -> Result<(Vec<Value>, u64)> {
    let text = fs::read_to_string(path).context("reading a segment")?;
    let mut records = Vec::new();
    let mut offset = position;
    for line in text
        .lines()
        .skip(usize::try_from(position).unwrap_or(usize::MAX))
    {
        if records.len() >= limit {
            break;
        }
        if line.is_empty() {
            offset += 1;
            continue;
        }
        records.push(serde_json::from_str(line).context("reading a record")?);
        offset += 1;
    }

    Ok((records, offset))
}

/// Refuses a name that would escape the store, for a caller that only has one.
pub fn check_name(name: &str) -> Result<()> {
    if safe(name).is_none() {
        bail!("`{name}` is not a name this store accepts");
    }

    Ok(())
}
