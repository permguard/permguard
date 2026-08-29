// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Config class: typed runtime settings assembled from layered inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::api::Disclosure;
use crate::audit::AuditDestination;
use crate::config_section::{AnyConfigSection, ConfigSection};
use crate::keys::KEY_SET_MAX_AGE;
use crate::limits::{Limits, PeerBlock};
use crate::logging::{LogFormat, LogLevel};
use crate::peer::AllowedPeer;
use crate::realm::{
    EXCHANGE_ON_UNMATCHED_SCOPE_REJECT, EXCHANGE_SOURCE_FORMAT_JWT,
    EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN, ExchangeProfileConfig, RealmConfig, RealmInput,
    TokenInitialExpiryPolicy, TrustedAttesterConfig,
};
use crate::secrets::{SecretProvider, SecretRef};
use crate::tls::TlsSettings;

/// Runtime setting key for the product version.
pub const SETTING_VERSION: &str = "PERMGUARD_VERSION";

/// Runtime setting key for the banner copyright year.
pub const SETTING_COPYRIGHT_YEAR: &str = "PERMGUARD_COPYRIGHT_YEAR";

/// Runtime setting key for the banner copyright holder.
pub const SETTING_COPYRIGHT_HOLDER: &str = "PERMGUARD_COPYRIGHT_HOLDER";

/// Runtime setting key for the directory this deployment keeps everything in.
///
/// This is the volume: secrets, transport material and whatever the server writes all live inside
/// it, and every relative path in the configuration resolves against it. A container points it at a
/// mount; a developer leaves it at the default and finds `.volume` beside the repository.
///
/// One setting instead of three, because the three were never independent: a deployment that moved
/// its secrets somewhere else moved all of it.
pub const SETTING_WORKING_DIR: &str = "PERMGUARD_WORKING_DIR";

/// Runtime setting key for whether the server may create material it was not given.
pub const SETTING_AUTOGENERATE: &str = "PERMGUARD_AUTOGENERATE";

/// Runtime setting key for whether this deployment is somebody's laptop.
///
/// One switch, stated once, that every other relaxation has to be justified against. Without it a
/// build ends up with a handful of individually reasonable conveniences — generate what is missing,
/// accept any client the authority signed, warn instead of refuse — each of which is right in
/// development and none of which is right in production, and no single place to read which of the
/// two you are looking at.
pub const SETTING_DEVELOPMENT_MODE: &str = "PERMGUARD_DEVELOPMENT_MODE";

/// Runtime setting key for the public URL this deployment is reached at.
pub const SETTING_ISSUER: &str = "PERMGUARD_ISSUER";

/// Runtime setting key for the path the public surface is mounted under.
pub const SETTING_PUBLIC_PATH_PREFIX: &str = "PERMGUARD_PUBLIC_PATH_PREFIX";

/// Runtime setting key for the public HTTP listen address.
pub const SETTING_PUBLIC_HTTP_ADDR: &str = "PERMGUARD_PUBLIC_HTTP_ADDR";

/// Runtime setting key for whether the public HTTP routes are served.
pub const SETTING_PUBLIC_HTTP_ENABLED: &str = "PERMGUARD_PUBLIC_HTTP_ENABLED";

/// Runtime setting key for the public gRPC listen address.
pub const SETTING_PUBLIC_GRPC_ADDR: &str = "PERMGUARD_PUBLIC_GRPC_ADDR";

/// Runtime setting key for whether the public gRPC routes are served.
pub const SETTING_PUBLIC_GRPC_ENABLED: &str = "PERMGUARD_PUBLIC_GRPC_ENABLED";

/// Runtime setting key for the telemetry listen address.
pub const SETTING_TELEMETRY_ADDR: &str = "PERMGUARD_TELEMETRY_ADDR";

/// Runtime setting key for OTLP trace export: off unless said otherwise.
///
/// When on, spans leave over OTLP/gRPC from a dedicated background thread with a bounded queue:
/// a collector that is down means dropped spans and a warning, never a slower or failing request.
pub const SETTING_OTEL_ENABLED: &str = "PERMGUARD_OTEL_ENABLED";

/// Runtime setting key for the OTLP collector endpoint.
pub const SETTING_OTEL_ENDPOINT: &str = "PERMGUARD_OTEL_ENDPOINT";

/// Runtime setting key for the trace sampling ratio, `0.0`..=`1.0`.
pub const SETTING_OTEL_SAMPLE_RATE: &str = "PERMGUARD_OTEL_SAMPLE_RATE";

/// Runtime setting key for the admin listen address.
pub const SETTING_ADMIN_ADDR: &str = "PERMGUARD_ADMIN_ADDR";

/// Runtime setting keys for the TLS material of each surface.
///
/// Three surfaces, three sets, because they answer different questions. The public one and the
/// administrative one can demand a client certificate; telemetry cannot, and that is deliberate — it
/// is scraped by a collector and probed by a kubelet, neither of which should need a client identity
/// to ask whether the process is alive.
pub const SETTING_PUBLIC_TLS_CERT: &str = "PERMGUARD_PUBLIC_TLS_CERT";
/// Private key of [`SETTING_PUBLIC_TLS_CERT`].
pub const SETTING_PUBLIC_TLS_KEY: &str = "PERMGUARD_PUBLIC_TLS_KEY";
/// Authority client certificates on the public surface must be signed by.
pub const SETTING_PUBLIC_TLS_CLIENT_CA: &str = "PERMGUARD_PUBLIC_TLS_CLIENT_CA";
/// Revocation list client certificates on the public surface are checked against.
pub const SETTING_PUBLIC_TLS_CRL: &str = "PERMGUARD_PUBLIC_TLS_CRL";
/// Lowest protocol version the public surface accepts.
pub const SETTING_PUBLIC_TLS_MIN_VERSION: &str = "PERMGUARD_PUBLIC_TLS_MIN_VERSION";
/// Which peers the public surface answers, of everybody the client authority signed.
///
/// Entries as `cn:name`, `dn:subject` or `sha256:<hex>`, one per line — a `dn:` contains commas,
/// so a comma cannot separate entries. Setting it
/// requires [`SETTING_PUBLIC_TLS_CLIENT_CA`]: without a demanded certificate there is no identity to
/// check, and a list nothing can satisfy is a misconfiguration, not a policy.
pub const SETTING_PUBLIC_TLS_ALLOW: &str = "PERMGUARD_PUBLIC_TLS_ALLOW";
/// Whether the public surface discloses the build it is: version and commit on `/version` and in
/// gRPC `GetInfo`. On by default — `permguard inspect` is built on it — and a deployment that would
/// rather not hand fingerprinting material to whoever can open a socket turns it off; the plane and
/// product names stay, so `inspect` still identifies what answered.
pub const SETTING_PUBLIC_DISCLOSE_BUILD: &str = "PERMGUARD_PUBLIC_DISCLOSE_BUILD";
/// How much an error on the public surface says about the inside: `full` or `minimal`.
///
/// Left unset, `development_mode` decides — full on a workstation, minimal everywhere else — so the
/// safe posture is the one a deployment gets by saying nothing.
pub const SETTING_PUBLIC_ERROR_DETAIL: &str = "PERMGUARD_PUBLIC_ERROR_DETAIL";

/// Certificate chain the administrative surface presents.
pub const SETTING_ADMIN_TLS_CERT: &str = "PERMGUARD_ADMIN_TLS_CERT";
/// Private key of [`SETTING_ADMIN_TLS_CERT`].
pub const SETTING_ADMIN_TLS_KEY: &str = "PERMGUARD_ADMIN_TLS_KEY";
/// Authority client certificates on the administrative surface must be signed by.
pub const SETTING_ADMIN_TLS_CLIENT_CA: &str = "PERMGUARD_ADMIN_TLS_CLIENT_CA";
/// Revocation list client certificates on the administrative surface are checked against.
pub const SETTING_ADMIN_TLS_CRL: &str = "PERMGUARD_ADMIN_TLS_CRL";
/// Lowest protocol version the administrative surface accepts.
pub const SETTING_ADMIN_TLS_MIN_VERSION: &str = "PERMGUARD_ADMIN_TLS_MIN_VERSION";

/// Runtime setting key for the peers the administrative surface answers.
///
/// One entry per line — see [`AllowedPeer`] for the forms. A newline
/// rather than a comma because a distinguished name contains commas, and a separator that appears
/// inside the values it separates is a parser waiting to split somebody's identity in half.
pub const SETTING_ADMIN_ALLOW: &str = "PERMGUARD_ADMIN_ALLOW";

/// Certificate chain the telemetry surface presents.
pub const SETTING_TELEMETRY_TLS_CERT: &str = "PERMGUARD_TELEMETRY_TLS_CERT";
/// Private key of [`SETTING_TELEMETRY_TLS_CERT`].
pub const SETTING_TELEMETRY_TLS_KEY: &str = "PERMGUARD_TELEMETRY_TLS_KEY";
/// Lowest protocol version the telemetry surface accepts.
pub const SETTING_TELEMETRY_TLS_MIN_VERSION: &str = "PERMGUARD_TELEMETRY_TLS_MIN_VERSION";

/// Runtime setting key for whether transport material is re-read while the server runs.
///
/// On by default. Certificates are renewed on a schedule nobody controls from inside the process,
/// and the alternative to noticing is a restart — which means either an outage every ninety days or,
/// far more often, a certificate that quietly expires because nobody wanted the outage.
pub const SETTING_TLS_RELOAD: &str = "PERMGUARD_TLS_RELOAD";

/// Runtime setting key for how often transport material is re-read.
pub const SETTING_TLS_RELOAD_INTERVAL: &str = "PERMGUARD_TLS_RELOAD_INTERVAL";

/// Runtime setting keys for what a surface refuses to spend on any one client.
///
/// One set for every surface — see [`Limits`] for why, and for what each of them stops.
pub const SETTING_LIMITS_CONNECTIONS: &str = "PERMGUARD_LIMITS_CONNECTIONS";
/// How many of one surface's sockets a single address may hold. Zero disables the bound.
pub const SETTING_LIMITS_CONNECTIONS_PER_PEER: &str = "PERMGUARD_LIMITS_CONNECTIONS_PER_PEER";
/// Addresses exempt from the per-address bound, comma-separated: `10.0.0.1, 192.168.0.0/16, ::1`.
pub const SETTING_LIMITS_PEER_EXEMPT: &str = "PERMGUARD_LIMITS_PEER_EXEMPT";
/// How long one connection may exist. Zero leaves it unbounded, which is the default.
pub const SETTING_LIMITS_CONNECTION_LIFETIME: &str = "PERMGUARD_LIMITS_CONNECTION_LIFETIME";
/// How long a response write may make no progress before the client is given up on.
pub const SETTING_LIMITS_WRITE_STALL_TIMEOUT: &str = "PERMGUARD_LIMITS_WRITE_STALL_TIMEOUT";
/// How many bytes one request head may carry.
pub const SETTING_LIMITS_HEADER_BYTES: &str = "PERMGUARD_LIMITS_HEADER_BYTES";
/// How many requests one surface has in flight at once.
pub const SETTING_LIMITS_CONCURRENT_REQUESTS: &str = "PERMGUARD_LIMITS_CONCURRENT_REQUESTS";
/// How long one request may take before it is given up on.
pub const SETTING_LIMITS_REQUEST_TIMEOUT: &str = "PERMGUARD_LIMITS_REQUEST_TIMEOUT";
/// How long a client has to finish a TLS handshake.
pub const SETTING_LIMITS_HANDSHAKE_TIMEOUT: &str = "PERMGUARD_LIMITS_HANDSHAKE_TIMEOUT";
/// How long a client has to send a complete request head.
pub const SETTING_LIMITS_HEADER_TIMEOUT: &str = "PERMGUARD_LIMITS_HEADER_TIMEOUT";
/// How many bytes one request body may carry.
pub const SETTING_LIMITS_BODY_BYTES: &str = "PERMGUARD_LIMITS_BODY_BYTES";

/// Runtime setting key for how much the build says.
pub const SETTING_LOG_LEVEL: &str = "PERMGUARD_LOG_LEVEL";

/// Runtime setting key for the shape records are written in.
pub const SETTING_LOG_FORMAT: &str = "PERMGUARD_LOG_FORMAT";

/// Runtime setting key for how long shutdown is given before the process exits anyway.
pub const SETTING_SHUTDOWN_TIMEOUT: &str = "PERMGUARD_SHUTDOWN_TIMEOUT";

/// Runtime setting key for where secrets are resolved from.
pub const SETTING_SECRETS_PROVIDER: &str = "PERMGUARD_SECRETS_PROVIDER";

/// Runtime setting key for the directory the `directory` provider reads.
pub const SETTING_SECRETS_DIRECTORY: &str = "PERMGUARD_SECRETS_DIRECTORY";

/// Runtime setting key for the variable prefix the `environment` provider reads.
pub const SETTING_SECRETS_ENV_PREFIX: &str = "PERMGUARD_SECRETS_ENV_PREFIX";

/// Runtime setting key for whether audit subjects are pseudonymised.
pub const SETTING_AUDIT_PSEUDONYM_ENABLED: &str = "PERMGUARD_AUDIT_PSEUDONYM_ENABLED";

/// Runtime setting key for the secret the pseudonymisation key is resolved from.
///
/// A *reference*, not the key. A configuration file that carries key material is a file that has to
/// be protected like a key — encrypted at rest, kept out of version control, redacted in every bug
/// report — and every deployment gets that wrong eventually. Naming the secret instead means the file
/// carries nothing worth stealing, the same file works against a directory in development and a vault
/// in production, and rotating happens where keys live rather than by editing YAML.
pub const SETTING_AUDIT_PSEUDONYM_KEY_REF: &str = "PERMGUARD_AUDIT_PSEUDONYM_KEY_REF";

/// Runtime setting key for the version every pseudonym names.
pub const SETTING_AUDIT_PSEUDONYM_KEY_VERSION: &str = "PERMGUARD_AUDIT_PSEUDONYM_KEY_VERSION";

/// Runtime setting key for where the audit trail is written.
pub const SETTING_AUDIT_SINK: &str = "PERMGUARD_AUDIT_SINK";

/// Runtime setting key for the directory the file sink writes to.
pub const SETTING_AUDIT_DIRECTORY: &str = "PERMGUARD_AUDIT_DIRECTORY";

/// Runtime setting key for how long the file sink keeps a day of records.
pub const SETTING_AUDIT_RETENTION: &str = "PERMGUARD_AUDIT_RETENTION";
/// Whether refused operations are recorded in the audit trail as well as the log.
///
/// Off by default: the trail records what changed the world, and a caller's mistakes change
/// nothing — recording them would let anybody inflate the evidentiary record with bad requests.
/// A deployment that wants denied attempts on the record — a compliance regime that asks for
/// them, an exposed surface under watch — turns it on and gets `<operation>.refused` records.
pub const SETTING_AUDIT_REFUSALS: &str = "PERMGUARD_AUDIT_REFUSALS";

/// Runtime setting key for the largest NOTP transfer batch, in bytes.
///
/// Advertised in every negotiate response for the transport the request arrived on. It must
/// exceed the largest legal object (5 MB) plus framing overhead, and the matching transport
/// message limits must be configured above it — objects are never chunked.
pub const SETTING_NOTP_MAX_BATCH_BYTES: &str = "PERMGUARD_NOTP_MAX_BATCH_BYTES";

/// Runtime setting key for the most objects one NOTP batch may carry.
pub const SETTING_NOTP_MAX_BATCH_OBJECTS: &str = "PERMGUARD_NOTP_MAX_BATCH_OBJECTS";

/// Runtime setting key for the most objects one push delta may declare.
///
/// A preflight at negotiate and re-enforced at commit on actual state: the bound that stops an
/// authorized-but-compromised writer from declaring the world.
pub const SETTING_NOTP_MAX_PUSH_OBJECTS: &str = "PERMGUARD_NOTP_MAX_PUSH_OBJECTS";

/// Runtime setting key for the most bytes one push delta may declare.
pub const SETTING_NOTP_MAX_PUSH_BYTES: &str = "PERMGUARD_NOTP_MAX_PUSH_BYTES";

/// Runtime setting key for the storage quota of one ledger's objects, in bytes.
///
/// Checked at upload: valid orphans from abandoned pushes cost disk until collection, and this is
/// the ceiling that keeps them from costing the volume.
pub const SETTING_NOTP_LEDGER_QUOTA_BYTES: &str = "PERMGUARD_NOTP_LEDGER_QUOTA_BYTES";

/// Runtime setting keys for a mirroring plane's synchronization loop.
///
/// The *servers* it follows are a structured record and come from the configuration file (see
/// [`crate::mirrors`]); everything measurable about the loop is a flat setting, so a deployment can
/// tune a cadence from the environment without rewriting a file.
pub const SETTING_MIRRORS_ENABLED: &str = "PERMGUARD_MIRRORS_ENABLED";

/// How often the loop runs. A tick that arrives while the previous one is still working is skipped,
/// so this is a *cadence*, not a promise.
pub const SETTING_MIRRORS_INTERVAL: &str = "PERMGUARD_MIRRORS_INTERVAL";

/// How long one ledger may take before it is abandoned for this round.
///
/// Per ledger, deliberately: a ledger that cannot be reached must not consume the budget of every
/// other ledger, and a mirror that is one round stale is worth far more than a loop that stalls.
pub const SETTING_MIRRORS_TIMEOUT: &str = "PERMGUARD_MIRRORS_TIMEOUT";

/// How many ledgers are mirrored at once.
pub const SETTING_MIRRORS_PARALLELISM: &str = "PERMGUARD_MIRRORS_PARALLELISM";

/// The fraction of the interval spread randomly across ticks, `0.0`..=`0.5`.
///
/// Each round waits `interval ± (interval × jitter) / 2`, drawn again every round — so `0.1` means
/// ±5% of the interval, and a fleet that happens to align on its first tick does not stay aligned.
///
/// Without it, every replica of a plane wakes at the same instant and asks one control plane for
/// everything at once — the thundering herd that turns a rollout into an incident.
pub const SETTING_MIRRORS_JITTER: &str = "PERMGUARD_MIRRORS_JITTER";

/// How old a mirror's last verified synchronization may grow before the plane alarms.
///
/// The freshness half of the consistency model: authenticity and no-rollback are enforced before a
/// checkpoint moves, and this is the bound on *how long* a verified state stays trusted. `stale`
/// still serves — the alarm is the point — because refusing is a separate, harder decision that
/// [`SETTING_MIRRORS_EXPIRE_AFTER`] makes. Unset (or `0s`) means no bound, which is the right
/// default for many deployments; having no way to set one is not.
pub const SETTING_MIRRORS_STALE_AFTER: &str = "PERMGUARD_MIRRORS_STALE_AFTER";

/// How old a mirror's last verified synchronization may grow before the plane refuses to answer
/// from it (`503`), rather than keep deciding on a state that may have revoked somebody since.
///
/// The right number is a risk decision nobody can make centrally — a revocation that matters makes
/// "indefinitely" wrong, and a flaky link makes "minutes" wrong. Unset (or `0s`) means no bound.
pub const SETTING_MIRRORS_EXPIRE_AFTER: &str = "PERMGUARD_MIRRORS_EXPIRE_AFTER";

/// Runtime setting keys for the store's own maintenance: reclaiming objects nothing references.
///
/// A content-addressed store only ever adds. Objects are uploaded before the commit that references
/// them, so a push that never commits — a client that lost its connection, a conflict that was not
/// retried — leaves objects nothing will ever reach. Left alone they are a slow leak of the one
/// resource an operator cannot get back without downtime: disk.
pub const SETTING_GC_ENABLED: &str = "PERMGUARD_STORAGE_GC_ENABLED";

/// How often the store is swept.
pub const SETTING_GC_INTERVAL: &str = "PERMGUARD_STORAGE_GC_INTERVAL";

/// How old an unreachable object must be before it may be removed.
///
/// **This is the safety property, not a tuning knob.** During a push, objects are legitimately
/// unreachable for as long as the transfer takes: a sweep that ignored their age would delete the
/// upload of every push in flight. The window has to comfortably exceed the slowest legitimate
/// push, which is why the default is a day and not a minute.
pub const SETTING_GC_GRACE: &str = "PERMGUARD_STORAGE_GC_GRACE";

/// Runtime setting keys for the decision path: what a data plane keeps in memory so an
/// authorization check never touches a disk.
///
/// A compiled partition — every policy parsed, the engine's own program built, the schema
/// checked — is what answers a request. Building one costs milliseconds and reading the objects
/// costs a disk; keeping it costs memory. These are the two bounds that decide how much.
pub const SETTING_AUTHZ_CACHE_PARTITIONS: &str = "PERMGUARD_AUTHZ_CACHE_PARTITIONS";

/// How many bytes of compiled partitions may be held before the least recently used are dropped.
///
/// Sizes accept `k`/`M`/`G`. A ledger with a large policy set is heavy: this is the bound that
/// keeps a PDP inside its container limit instead of discovering it at the OOM killer.
pub const SETTING_AUTHZ_CACHE_BYTES: &str = "PERMGUARD_AUTHZ_CACHE_BYTES";

/// The most evaluations one boxcarred request may carry.
///
/// A caller who asks for ten thousand decisions in one payload is either confused or hostile, and
/// either way the answer is a refusal rather than a stalled worker.
pub const SETTING_AUTHZ_MAX_EVALUATIONS: &str = "PERMGUARD_AUTHZ_MAX_EVALUATIONS";

/// How many pieces of blocking work this plane may have in flight at once.
///
/// Evaluating a policy and writing a decision record both wait — on a CPU that is not yielding, on
/// a disk that has not finished — and neither may run on a runtime worker. They run on a pool, and
/// this is its size: reached, the plane refuses immediately rather than queueing behind work it
/// cannot bound. It is the number that decides whether a stalled disk or a provider that stopped
/// returning shows up as refusals while the plane can still produce them, or as a plane that
/// accumulates until memory decides, so it is worth being able to set.
pub const SETTING_MAX_BLOCKING: &str = "PERMGUARD_MAX_BLOCKING";

/// Runtime setting keys for the decision log: what a plane records about what it decided, and
/// where it sends it.
///
/// Off by default. A decision log is a security control and a data-protection surface at the same
/// time, and neither is something to switch on for a deployment that did not ask for it.
pub const SETTING_LOG_ENABLED: &str = "PERMGUARD_DECISIONS_LOG_ENABLED";

/// This plane's name in the log, and half of every stream identity.
///
/// Required when the log is on. A hostname fallback is convenient and wrong the first time two
/// replicas run on one host: two producers sharing a `pdp.id` produce two records at one
/// `(stream, seq)`, which closes a stream permanently at the far end.
pub const SETTING_LOG_PDP_ID: &str = "PERMGUARD_DECISIONS_LOG_PDP_ID";

/// Where the durable local record lives, under the working directory.
///
/// Distinct from where a control plane *keeps* what it receives
/// (`SETTING_DECISION_STORE_DIRECTORY`), and that is not a style choice: in the
/// all-in-one both planes share one volume, and a spool writing its segments
/// into the store's directory would put a producer's private working state
/// among the records an auditor reads.
pub const SETTING_LOG_SPOOL_DIRECTORY: &str = "PERMGUARD_DECISIONS_LOG_SPOOL_DIRECTORY";

/// How many bytes of **decision records** the spool may hold. Accepts `k`/`M`/`G`.
///
/// The terminal record that ends a stream is reserved outside this bound, because a producer that
/// cannot write its last record cannot legally discard anything and cannot continue at all.
pub const SETTING_LOG_SPOOL_BYTES: &str = "PERMGUARD_DECISIONS_LOG_SPOOL_BYTES";

// ─── The temporal event journal ──────────────────────────────────────────────
//
// Its own settings, not the decision log's, because the two are not the same
// subject wearing different names. A decision record is evidence: once shipped
// and acknowledged the producer may forget it. An event record is evidence
// **and** an input — it is the history a temporal policy reads — so its
// retention is decided by what the loaded policies still look at, and there is
// no `on_full: open` for it at all.

/// Whether this plane serves the temporal interface.
///
/// Off unless a deployment says otherwise, like every other subsystem that
/// writes to disk: a plane that keeps a durable history should be a plane
/// somebody chose to run.
pub const SETTING_EVENTS_ENABLED: &str = "PERMGUARD_EVENTS_ENABLED";

/// This plane's name as an event producer, stable across restarts.
///
/// Required when the interface is on. Falling back to a hostname is convenient
/// and wrong the first time two replicas share a host — and here it is worse
/// than for the decision log, because a producer id names a hash chain: two
/// planes sharing one would each be appending to a stream the other also
/// claims.
pub const SETTING_EVENTS_PRODUCER_ID: &str = "PERMGUARD_EVENTS_PRODUCER_ID";

/// Where the journals live, under the volume.
pub const SETTING_EVENTS_DIRECTORY: &str = "PERMGUARD_EVENTS_DIRECTORY";

/// The bound on one ledger's event records, excluding the reserve.
pub const SETTING_EVENTS_MAX_BYTES: &str = "PERMGUARD_EVENTS_MAX_BYTES";

/// When a segment is closed and a new one started.
pub const SETTING_EVENTS_SEGMENT_BYTES: &str = "PERMGUARD_EVENTS_SEGMENT_BYTES";

/// The largest single event record a journal accepts.
pub const SETTING_EVENTS_MAX_RECORD_BYTES: &str = "PERMGUARD_EVENTS_MAX_RECORD_BYTES";

/// The shortest history this deployment promises to keep.
///
/// A floor, not the answer: the requirement is this plus what the loaded
/// policies' longest `max_window` asks for, and a configuration shorter than
/// that is refused rather than quietly serving policies whose windows have
/// been emptied underneath them.
pub const SETTING_EVENTS_RETENTION_MINIMUM: &str = "PERMGUARD_EVENTS_RETENTION_MINIMUM";

/// How late an occurrence may arrive and still be recorded.
pub const SETTING_EVENTS_ALLOWED_LATENESS: &str = "PERMGUARD_EVENTS_ALLOWED_LATENESS";

/// How far a caller's clock may run ahead of this one.
pub const SETTING_EVENTS_CLOCK_SKEW: &str = "PERMGUARD_EVENTS_CLOCK_SKEW";

/// How long a group commit may wait to amortise an `fsync` across a batch.
///
/// A latency budget, never a durability one: a receipt is still withheld until the record is on
/// disk. What this buys is that ten submissions arriving together cost one flush rather than ten.
pub const SETTING_EVENTS_GROUP_COMMIT_DELAY: &str = "PERMGUARD_EVENTS_GROUP_COMMIT_MAX_DELAY";

/// Whether this deployment will serve Dogwood partitions.
///
/// The language is compiled in either way — a language is a build, not a deployment action, so
/// what interprets policy is exactly what was reviewed, signed and shipped. What this gates is
/// whether a *ledger* that names it will be served, and it is off by default because Dogwood's
/// wire and replication contracts are `v1alpha1`: a deployment should adopt them deliberately.
///
/// A manifest naming Dogwood on a plane that has not turned this on is refused at load, by name,
/// rather than served and then discovered to behave differently after an upgrade.
pub const SETTING_EXPERIMENTAL_DOGWOOD: &str = "PERMGUARD_EXPERIMENTAL_DOGWOOD_ENABLED";

/// The prefix and suffix an `experimental.<name>.enabled` setting is spelled with.
///
/// Kept as a pattern rather than a list of constants because the set of provisional runtimes is not
/// this crate's to know: a language declares itself experimental, and the deployment opts in by
/// name. A new one must not require a new constant here — that is precisely the coupling that made
/// the previous single `dogwood` flag impossible to extend.
/// The name Dogwood registers itself under, for the one convenience accessor that names it.
///
/// The gate itself never uses this: it asks each language whether it is experimental and what it is
/// called. This exists so the temporal event path — which is Dogwood's and nothing else's today —
/// can ask its question without spelling the string at four call sites.
pub const EXPERIMENTAL_DOGWOOD: &str = "dogwood";

pub const SETTING_EXPERIMENTAL_PREFIX: &str = "PERMGUARD_EXPERIMENTAL_";
pub const SETTING_EXPERIMENTAL_SUFFIX: &str = "_ENABLED";

/// The setting key that opts a deployment into the experimental runtime `name`.
pub fn experimental_setting_key(name: &str) -> String {
    format!(
        "{SETTING_EXPERIMENTAL_PREFIX}{}{SETTING_EXPERIMENTAL_SUFFIX}",
        name.to_ascii_uppercase().replace('-', "_")
    )
}

/// The runtime name an `experimental.<name>.enabled` key opts into, when a key is one.
pub fn experimental_setting_name(key: &str) -> Option<String> {
    key.strip_prefix(SETTING_EXPERIMENTAL_PREFIX)?
        .strip_suffix(SETTING_EXPERIMENTAL_SUFFIX)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase().replace('_', "-"))
}

/// Which history a decision ranges over: `local`, `shared-eventual` or `shared-bounded`.
///
/// `local` unless a deployment says otherwise, and deliberately: a plane that silently began
/// deciding against another plane's events would change what its policies mean without anybody
/// choosing that.
pub const SETTING_EVENTS_PULL_MODE: &str = "PERMGUARD_EVENTS_PULL_MODE";

/// How often the pull worker asks the control plane for more.
pub const SETTING_EVENTS_PULL_INTERVAL: &str = "PERMGUARD_EVENTS_PULL_INTERVAL";

/// How stale imported history may be before `shared-bounded` fails decisions closed.
pub const SETTING_EVENTS_PULL_MAX_STALENESS: &str = "PERMGUARD_EVENTS_PULL_MAX_STALENESS";

/// How old the oldest unshipped record may be before the stream must end.
pub const SETTING_LOG_SPOOL_AGE: &str = "PERMGUARD_DECISIONS_LOG_SPOOL_AGE";

/// How large a batch may grow before it is shipped.
pub const SETTING_LOG_BATCH_BYTES: &str = "PERMGUARD_DECISIONS_LOG_BATCH_BYTES";

/// How long a batch may wait before it is shipped anyway.
pub const SETTING_LOG_BATCH_INTERVAL: &str = "PERMGUARD_DECISIONS_LOG_BATCH_INTERVAL";

/// What a full spool means: `open` keeps answering and ends the stream with a signed
/// discontinuity; `closed` refuses to decide rather than decide unrecorded.
///
/// The one decision only a deployment can make, so it is stated rather than defaulted quietly.
pub const SETTING_LOG_ON_FULL: &str = "PERMGUARD_DECISIONS_LOG_ON_FULL";

/// The rate at which permits are recorded, between `0.0` and `1.0`.
///
/// Denies and errors are never sampled, whatever this says: a log that drops refusals is not an
/// audit trail.
pub const SETTING_LOG_SAMPLE_PERMITS: &str = "PERMGUARD_DECISIONS_LOG_SAMPLE_PERMITS";

/// Runtime setting key for the secret input commitments are taken under.
///
/// Required when the decision log is on. A commitment keyed by something public — a hostname, the
/// producer's own name, anything that travels in the records — is a bare digest wearing a hat, and
/// a bare digest of a low-entropy value is a dictionary away from the value.
pub const SETTING_LOG_COMMITMENT_KEY_REF: &str = "PERMGUARD_DECISIONS_LOG_COMMITMENT_KEY_REF";

/// Which version of that key, recorded in every marker so a reader can tell a different value from
/// a different key.
pub const SETTING_LOG_COMMITMENT_KEY_VERSION: &str =
    "PERMGUARD_DECISIONS_LOG_COMMITMENT_KEY_VERSION";

/// Runtime setting keys for the decision-log store: where a control plane keeps what data planes
/// ship it.
///
/// Off by default, like the producer half: a plane that receives nothing should not create a
/// store, and a deployment that has not decided its retention should not be given one by accident.
pub const SETTING_DECISION_STORE_ENABLED: &str = "PERMGUARD_DECISIONS_STORE_ENABLED";

/// Where the segments live, under the working directory.
pub const SETTING_DECISION_STORE_DIRECTORY: &str = "PERMGUARD_DECISIONS_STORE_DIRECTORY";

/// Whether this control plane receives and serves an event store.
///
/// Off by default, like the decision store: a plane that receives nothing should not create one,
/// and a deployment that has not decided its retention should not be given one by accident.
pub const SETTING_EVENT_STORE_ENABLED: &str = "PERMGUARD_EVENTS_STORE_ENABLED";

/// Where the event store's segments live, under the working directory.
pub const SETTING_EVENT_STORE_DIRECTORY: &str = "PERMGUARD_EVENTS_STORE_DIRECTORY";

/// How long a tenant's events are kept before sealed segments are dropped.
///
/// A ceiling on the store rather than on any one policy: the *plane that decides* keeps what its
/// own `max_window` requires, and this is how long the whole history stays available to read,
/// export and verify.
pub const SETTING_EVENT_STORE_RETENTION: &str = "PERMGUARD_EVENTS_STORE_RETENTION";

/// How long records are kept before their segments leave.
///
/// This is the bound on how far behind a reader may fall, and it is stated rather than defaulted
/// to forever: a decision log that never forgets is a data-protection liability, and one that
/// forgets without saying so makes a consumer report a clean run it did not have.
pub const SETTING_DECISION_STORE_RETENTION: &str = "PERMGUARD_DECISIONS_STORE_RETENTION";

/// Runtime setting key for NOTP batch compression: `deflate` (default) or `none`.
///
/// Advertised in every negotiate response; a client that cannot speak it sends and asks for
/// raw batches — the algorithm is negotiated, never assumed. Objects at rest are always
/// compressed; this governs only the wire.
pub const SETTING_NOTP_COMPRESSION: &str = "PERMGUARD_NOTP_COMPRESSION";

/// Runtime setting key for whether the control plane composes its signing ring — the ring that
/// signs what the control plane serves (git-like head statements today). Absent, it follows
/// `keys.enabled`. Deliberately not the operations ring that seals the audit trail.
pub const SETTING_CONTROL_KEYS_ENABLED: &str = "PERMGUARD_CONTROL_KEYS_ENABLED";

/// Runtime setting key for where the control plane's signing ring lives.
pub const SETTING_CONTROL_KEYS_DIRECTORY: &str = "PERMGUARD_CONTROL_KEYS_DIRECTORY";

/// Runtime setting key for whether the data plane composes its signing ring — the ring that will
/// sign the decision responses it returns. Absent, it follows `keys.enabled`: the signing rings
/// are part of the model on every plane, not an option bolted onto one.
pub const SETTING_DATA_KEYS_ENABLED: &str = "PERMGUARD_DATA_KEYS_ENABLED";

/// Runtime setting key for where the data plane's signing ring lives.
pub const SETTING_DATA_KEYS_DIRECTORY: &str = "PERMGUARD_DATA_KEYS_DIRECTORY";

/// Runtime setting key for whether this deployment publishes signing keys at all.
pub const SETTING_KEYS_ENABLED: &str = "PERMGUARD_KEYS_ENABLED";

/// Runtime setting key for the directory the key ring lives in.
pub const SETTING_KEYS_DIRECTORY: &str = "PERMGUARD_KEYS_DIRECTORY";

/// Runtime setting key for how long a new key is published before it starts signing.
///
/// This is the one setting an operator gets wrong in the direction that causes an outage: it has to
/// be longer than the longest cache a verifier might be holding, because a signature naming a key
/// that a verifier has not fetched yet fails for exactly as long as that cache lasts.
pub const SETTING_KEYS_PUBLISH_AHEAD: &str = "PERMGUARD_KEYS_PUBLISH_AHEAD";

/// Runtime setting key for how long a key signs before it is replaced.
pub const SETTING_KEYS_ROTATE_EVERY: &str = "PERMGUARD_KEYS_ROTATE_EVERY";

/// Runtime setting key for how long a retired key stays published.
///
/// The answer to "how far back must a signature still verify". A key dropped sooner than that makes
/// perfectly good signatures unverifiable, which is indistinguishable from forgery to whoever is
/// holding one.
pub const SETTING_KEYS_RETAIN: &str = "PERMGUARD_KEYS_RETAIN";

/// Runtime setting key for how often the key lifecycle is advanced.
///
/// One loop maintains every ring — the server's and each realm's — so this is one server-wide cadence,
/// not something a realm sets. A realm's `rotate_every` cannot take effect faster than this: the loop
/// only acts when it runs. A minute in production; development lowers it to watch a rotation happen.
pub const SETTING_KEYS_MAINTENANCE_INTERVAL: &str = "PERMGUARD_KEYS_MAINTENANCE_INTERVAL";

/// The key version a deployment that never rotated is on.
const DEFAULT_KEY_VERSION: &str = "v1";

/// How often transport material is re-read when nothing says otherwise.
///
/// Thirty seconds is short enough that a renewal is picked up before a monitoring system notices,
/// and long enough that four `stat` calls at that cadence are not worth measuring.
const DEFAULT_TLS_RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// How long a new key waits in the key set before it signs anything.
const DEFAULT_KEYS_PUBLISH_AHEAD: Duration = Duration::from_secs(60 * 60);

/// How long a key signs before it is replaced.
const DEFAULT_KEYS_ROTATE_EVERY: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How often the key lifecycle is advanced when nothing says otherwise.
///
/// A minute: the pass is a small file read that changes nothing almost every time, and a cadence tied
/// to the rotation windows would mean a deployment with a one-hour `publish_ahead` could be up to an
/// hour late to honour it.
const DEFAULT_KEYS_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// How long a retired key stays published.
///
/// A year, which is longer than most products would choose and deliberately so: Permguard is about
/// authority that continues, and a signature that stops verifying because the key ring was tidied is
/// the failure this product exists to prevent.
const DEFAULT_KEYS_RETAIN: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// How long a day of audit records is kept when nothing says otherwise.
const DEFAULT_AUDIT_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// NOTP transfer bounds: a batch comfortably above the 5 MB object ceiling, deltas sized for
/// policy ledgers (hundreds of small objects), and a ledger quota an order above that.
const DEFAULT_NOTP_MAX_BATCH_BYTES: u64 = 8 * 1024 * 1024;
/// Batches ride compressed unless a deployment turns it off: policy text deflates well.
const DEFAULT_NOTP_COMPRESSION: bool = true;

/// Synchronization defaults: a cadence a PDP can hold without noticing, a per-ledger budget wide
/// enough for a first mirror of a real ledger, and enough spread that replicas do not stampede.
const DEFAULT_MIRRORS_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_MIRRORS_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_MIRRORS_PARALLELISM: usize = 4;
const DEFAULT_MIRRORS_JITTER: f64 = 0.1;

/// Maintenance defaults: sweep four times a day, and never touch anything younger than a day.
/// The interval is about how promptly space returns; the grace period is about correctness, and it
/// is deliberately far wider than any push this protocol can take.
/// The shortest grace period this server will accept.
///
/// A floor rather than a warning, because the failure it prevents is silent and unrecoverable:
/// below it, a sweep can delete the objects of a push that is still uploading, and the client will
/// only find out when its commit is refused for a missing object it successfully sent.
const MINIMUM_GC_GRACE: Duration = Duration::from_secs(15 * 60);
const DEFAULT_GC_ENABLED: bool = true;
const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const DEFAULT_GC_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// Decision-path defaults: enough compiled partitions for a plane that serves a handful of
/// ledgers, and a memory bound a small container can hold. Both are meant to be raised by a
/// deployment that knows its ledgers.
const DEFAULT_AUTHZ_CACHE_PARTITIONS: usize = 64;
const DEFAULT_AUTHZ_CACHE_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_AUTHZ_MAX_EVALUATIONS: usize = 256;

/// The default bound on concurrent blocking work.
///
/// High enough that a plane answering ordinary traffic never meets it, low enough that work which
/// has stopped returning cannot take the process with it.
const DEFAULT_MAX_BLOCKING: usize = 64;

/// The default bound, for a component built before a configuration is read.
pub fn default_max_blocking() -> usize {
    DEFAULT_MAX_BLOCKING
}

/// Decision-log defaults. Off, because a decision log is a security control and a
/// data-protection surface at once, and neither is switched on for a deployment that did not ask.
/// The rest are the shape a deployment that *does* ask almost always wants: half a gigabyte of
/// spool and a day of it, a batch every second or every quarter megabyte, every permit recorded,
/// and a full spool that keeps answering rather than refusing.
const DEFAULT_LOG_SPOOL_DIRECTORY: &str = "data/decisions/spool";

/// Where the temporal event journals live, under the volume.
pub const DEFAULT_EVENTS_DIRECTORY: &str = "data/events";
/// Where the control plane's event store lives, under the volume.
pub const DEFAULT_EVENT_STORE_DIRECTORY: &str = "data/events/store";
/// How long a control plane keeps a tenant's events before dropping sealed segments.
///
/// Thirty days: long enough that an investigation into something noticed a week later still has
/// the evidence, and short enough that a deployment which never thought about it does not
/// accumulate history for ever.
pub const DEFAULT_EVENT_STORE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// The bound on one ledger's event records, excluding the reserve.
pub const DEFAULT_EVENTS_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// When a journal segment is closed and a new one started.
pub const DEFAULT_EVENTS_SEGMENT_BYTES: u64 = 32 * 1024 * 1024;
/// The largest single event record a journal accepts.
pub const DEFAULT_EVENTS_MAX_RECORD_BYTES: u64 = 1024 * 1024;
/// The shortest history a deployment promises to keep, before the policies' own requirement.
///
/// Two days, which comfortably covers Dogwood's own 24-hour default `max_window` plus the lateness
/// and skew a journal has to allow on top of it. A deployment whose policies look further back
/// raises this, and one that does not is refused rather than silently emptying their windows.
pub const DEFAULT_EVENTS_RETENTION_MINIMUM: Duration = Duration::from_secs(48 * 60 * 60);
/// How late an occurrence may arrive and still be recorded.
pub const DEFAULT_EVENTS_ALLOWED_LATENESS: Duration = Duration::from_secs(5 * 60);
/// How far a caller's clock may run ahead of this one.
pub const DEFAULT_EVENTS_CLOCK_SKEW: Duration = Duration::from_secs(30);
/// How long a group commit may wait to amortise an `fsync`.
pub const DEFAULT_EVENTS_GROUP_COMMIT_DELAY: Duration = Duration::from_millis(5);
/// How often the pull worker asks for more, when a deployment turns pull on.
pub const DEFAULT_EVENTS_PULL_INTERVAL: Duration = Duration::from_secs(2);
/// How stale imported history may be before `shared-bounded` fails decisions closed.
pub const DEFAULT_EVENTS_PULL_MAX_STALENESS: Duration = Duration::from_secs(10);

/// One ledger a plane imports history from, and the types it will import.
///
/// Structured rather than a scalar, because a subscription is three facts that must travel
/// together: a scalar form would be a string somebody has to parse, and a parse is a place two
/// spellings become two subscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullSubscription {
    pub zone: String,
    pub ledger: String,
    /// The registered event types. Part of the canonical filter set the read cursor is bound to,
    /// so widening it starts a new read rather than quietly widening one already in progress.
    pub event_types: Vec<String>,
}

/// Which history a decision ranges over.
///
/// The three are not degrees of the same thing: `local` decides against what this plane recorded,
/// and the other two decide against a history assembled from several planes. That is a different
/// answer to the same request, so it is a deployment's explicit choice rather than a default that
/// changes when a second plane appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consistency {
    /// Only what this plane recorded. The default.
    Local,
    /// Also whatever imported history has arrived, at the local watermark.
    ///
    /// Not strong consistency and never described as it: replication is asynchronous, so a
    /// decision ranges over what had arrived when it was made, and the response says which
    /// watermark that was.
    SharedEventual,
    /// As above, and decision events fail closed when the imported history is too stale.
    SharedBounded,
}

impl Consistency {
    /// The name a configuration writes, and a decision reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::SharedEventual => "shared-eventual",
            Self::SharedBounded => "shared-bounded",
        }
    }

    /// Whether this mode reads history other planes recorded.
    pub fn is_shared(self) -> bool {
        !matches!(self, Self::Local)
    }

    /// The mode a name spells, or `None` for one nobody defined.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim() {
            "local" => Some(Self::Local),
            "shared-eventual" => Some(Self::SharedEventual),
            "shared-bounded" => Some(Self::SharedBounded),
            _ => None,
        }
    }
}
const DEFAULT_LOG_SPOOL_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_LOG_SPOOL_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_LOG_BATCH_BYTES: u64 = 256 * 1024;
const DEFAULT_LOG_BATCH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_LOG_SAMPLE_PERMITS: f64 = 1.0;

/// Ninety days: long enough for the investigation that starts a quarter late, short enough that
/// nobody keeps personal data indefinitely by not choosing.
const DEFAULT_DECISION_STORE_DIRECTORY: &str = "data/decisions/store";
const DEFAULT_DECISION_STORE_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// The conventional local OTLP/gRPC collector endpoint.
const DEFAULT_OTEL_ENDPOINT: &str = "http://127.0.0.1:4317";
/// Everything, until somebody says otherwise: sampling is a scale decision.
const DEFAULT_OTEL_SAMPLE_RATE: f64 = 1.0;
const DEFAULT_NOTP_MAX_BATCH_OBJECTS: u64 = 1_000;
const DEFAULT_NOTP_MAX_PUSH_OBJECTS: u64 = 10_000;
const DEFAULT_NOTP_MAX_PUSH_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_NOTP_LEDGER_QUOTA_BYTES: u64 = 1024 * 1024 * 1024;

/// Where the key ring lives inside the volume when nothing says otherwise.
///
/// Under `operations/`: this is the ring that signs the system trail's seals, an internal duty whose
/// public keys are never served over HTTP. It sits beside the trail it protects and the secret that
/// pseudonymises it, so the whole record-keeping subsystem backs up as one unit. A realm issuing
/// tokens keeps those keys separately, at `realms/<name>/keys` — see [`Config::realm_token_keys_directory`].
const DEFAULT_KEYS_SUBDIRECTORY: &str = "operations/keys";

/// Where the audit trail is written inside the volume when nothing says otherwise.
const DEFAULT_AUDIT_SUBDIRECTORY: &str = "operations/audit";

/// How long shutdown gets before the process exits regardless.
///
/// Thirty seconds is what Kubernetes gives a pod by default between SIGTERM and SIGKILL, so a longer
/// budget here would be a budget the orchestrator never honours.
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a deployment that says nothing keeps everything.
///
/// Relative on purpose: it resolves beside whatever started the process, which for a developer is the
/// repository and for a container is the working directory the image sets.
const DEFAULT_WORKING_DIR: &str = ".volume";

/// Where secrets live inside the volume when nothing says otherwise.
///
/// Under `operations/`: the pseudonymisation key is part of protecting the record, so it lives with
/// the trail and the keys that seal it.
const DEFAULT_SECRETS_SUBDIRECTORY: &str = "operations/secrets";

const DEFAULT_VERSION: &str = "0.0.0";
const DEFAULT_COPYRIGHT_YEAR: &str = "0000";
const DEFAULT_COPYRIGHT_HOLDER: &str = "Permguard";

/// The inputs a configuration is assembled from, in the order they overwrite one another.
///
/// A struct with names rather than three arguments of the same type in a row. Three lists of
/// `(String, String)` as positional parameters are three chances to swap two of them, and a swap
/// here compiles, runs, passes every test that does not set the same key twice, and quietly decides
/// that a file baked into an image outranks what the deployment said. Naming them makes that
/// particular mistake unwritable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Layers {
    /// What the configuration file named on the command line declares.
    pub file: Vec<(String, String)>,
    /// What the process environment declares. Overwrites the file — see [`Config::from_layers`].
    pub environment: Vec<(String, String)>,
    /// What the invocation passed as flags. The last word.
    pub command_line: Vec<(String, String)>,
}

impl Layers {
    /// Builds an empty set of layers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds what the configuration file declares.
    pub fn with_file<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        self.file = inputs.into_iter().collect();

        self
    }

    /// Adds what the environment declares.
    pub fn with_environment<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        self.environment = inputs.into_iter().collect();

        self
    }

    /// Adds what the invocation passed as flags.
    pub fn with_command_line<I>(mut self, inputs: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        self.command_line = inputs.into_iter().collect();

        self
    }
}

/// Build-time values that participate in runtime configuration.
///
/// Every value is `&'static str`: these come from the compiled binary, and the command-line parser
/// needs the version string to outlive the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildSettings {
    version: &'static str,
    commit: &'static str,
    copyright_year: &'static str,
    copyright_holder: &'static str,
}

impl BuildSettings {
    /// Builds the configuration layer supplied by the compiled binary.
    pub fn new(
        version: &'static str,
        copyright_year: &'static str,
        copyright_holder: &'static str,
    ) -> Self {
        Self {
            version,
            // What a build that states nothing says — the same word build.rs falls back to when
            // neither the environment nor a repository can answer.
            commit: "unknown",
            copyright_year,
            copyright_holder,
        }
    }

    /// Names the commit this binary was built from.
    pub fn with_commit(mut self, commit: &'static str) -> Self {
        self.commit = commit;
        self
    }

    /// Returns the version the binary was compiled with.
    pub fn version(&self) -> &'static str {
        self.version
    }

    /// Returns the commit the binary was built from, or `unknown`.
    pub fn commit(&self) -> &'static str {
        self.commit
    }
}

/// Runtime settings combined from defaults, build metadata, environment, config files, and CLI.
///
/// Listen addresses have no built-in default: they come from the configuration file the command
/// names, optionally overridden by a command-line flag. Logging does have defaults, and they are the
/// production ones.
///
/// Beyond the typed settings, a binary can declare additional setting keys it understands. Declared
/// keys travel through the same precedence layers and are read back with [`Config::setting`]. An
/// undeclared key is discarded at every layer, so no ambient environment variable can ever reach the
/// configuration of a build that does not ask for it.
///
/// Beyond both of those, a build can add whole typed sections of its own — see
/// [`ConfigSection`] — which is how configuration that this
/// crate has never heard of travels to the code that understands it.
///
/// The type is deliberately not `PartialEq`: it carries sections whose types it does not know, and
/// comparing two configurations by equality would either be a lie or a comparison of pointers.
#[derive(Debug, Clone)]
pub struct Config {
    version: String,
    commit: String,
    copyright_year: String,
    copyright_holder: String,
    working_dir: Option<String>,
    autogenerate: bool,
    development_mode: bool,
    issuer: Option<String>,
    public_path_prefix: String,
    public_http_enabled: bool,
    public_http_addr: Option<String>,
    public_grpc_enabled: bool,
    public_grpc_addr: Option<String>,
    telemetry_addr: Option<String>,
    admin_addr: Option<String>,
    admin_allow: Vec<AllowedPeer>,
    disclose_build: bool,
    error_detail: Option<Disclosure>,
    log_level: LogLevel,
    log_format: LogFormat,
    public_tls: Option<TlsSettings>,
    admin_tls: Option<TlsSettings>,
    telemetry_tls: Option<TlsSettings>,
    tls_reload: bool,
    tls_reload_interval: Duration,
    limits: Limits,
    shutdown_timeout: Duration,
    secrets_provider: SecretProvider,
    secrets_directory: Option<String>,
    secrets_env_prefix: String,
    audit_destination: AuditDestination,
    audit_refusals: bool,
    notp_max_batch_bytes: u64,
    gc_enabled: bool,
    gc_interval: Duration,
    gc_grace: Duration,
    authz_cache_partitions: usize,
    authz_cache_bytes: u64,
    authz_max_evaluations: usize,
    max_blocking: usize,
    log_enabled: bool,
    log_pdp_id: String,
    log_spool_directory: String,
    log_spool_bytes: u64,
    events_enabled: bool,
    events_producer_id: String,
    events_directory: String,
    events_max_bytes: u64,
    events_segment_bytes: u64,
    events_max_record_bytes: u64,
    events_retention_minimum: Duration,
    events_allowed_lateness: Duration,
    events_clock_skew: Duration,
    events_group_commit_delay: Duration,
    events_pull_mode: Consistency,
    events_pull_interval: Duration,
    events_pull_max_staleness: Duration,
    /// What this deployment has opted into, by runtime name.
    ///
    /// A map rather than a field per runtime: which runtimes are provisional is decided by the
    /// languages this build carries, and a configuration type that had to name them would have to
    /// be edited every time one was added or graduated.
    experimental: BTreeMap<String, bool>,
    events_pull_ledgers: Vec<PullSubscription>,
    events_pull_producer_keys: Vec<crate::decisions::EventProducerSource>,
    log_spool_age: Duration,
    log_batch_bytes: u64,
    log_batch_interval: Duration,
    log_on_full_open: bool,
    log_sample_permits: f64,
    log_commitment_key_ref: Option<SecretRef>,
    log_commitment_key_version: String,
    log_destination: Option<crate::decisions::LogDestination>,
    events_destination: Option<crate::decisions::EventDestination>,
    log_include: crate::decisions::IncludeSection,
    decision_store_enabled: bool,
    decision_store_directory: String,
    event_store_enabled: bool,
    event_store_directory: String,
    event_store_retention: Duration,
    decision_store_retention: Duration,
    decision_producer_keys: Vec<String>,
    /// The published key sets of the producers this plane accepts *event* records from.
    ///
    /// Separate from the decision one because they are separate trust decisions: a deployment may
    /// receive decisions from planes it does not receive events from, and saying so should not
    /// require saying it twice everywhere else.
    event_producer_keys: Vec<crate::decisions::EventProducerSource>,
    notp_compression: bool,
    mirrors_enabled: bool,
    mirrors_interval: Duration,
    mirrors_timeout: Duration,
    mirrors_parallelism: usize,
    mirrors_jitter: f64,
    mirrors_stale_after: Option<Duration>,
    mirrors_expire_after: Option<Duration>,
    mirror_sources: Vec<crate::mirrors::MirrorSource>,
    otel_enabled: bool,
    otel_endpoint: String,
    otel_sample_rate: f64,
    notp_max_batch_objects: u64,
    notp_max_push_objects: u64,
    notp_max_push_bytes: u64,
    notp_ledger_quota_bytes: u64,
    audit_directory: Option<String>,
    audit_retention: Duration,
    audit_pseudonym_enabled: bool,
    audit_pseudonym_key_ref: Option<SecretRef>,
    audit_pseudonym_key_version: String,
    keys_enabled: bool,
    keys_directory: Option<String>,
    control_keys_enabled: Option<bool>,
    control_keys_directory: Option<String>,
    data_keys_enabled: Option<bool>,
    data_keys_directory: Option<String>,
    keys_publish_ahead: Duration,
    keys_rotate_every: Duration,
    keys_retain: Duration,
    keys_maintenance_interval: Duration,
    // The operations-keys lifecycle settings some layer explicitly declared, as opposed to defaulted.
    // Signing policy is security: `validate` refuses an enabled ring whose lifecycle was only defaulted,
    // and the typed `keys_*` fields alone cannot tell a stated value apart from the default it matches.
    keys_lifecycle_declared: BTreeSet<&'static str>,
    realms: Vec<RealmConfig>,
    declared: BTreeSet<String>,
    declared_values: BTreeMap<String, String>,
    sections: BTreeMap<&'static str, Arc<dyn AnyConfigSection>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: DEFAULT_VERSION.to_owned(),
            commit: "unknown".to_owned(),
            copyright_year: DEFAULT_COPYRIGHT_YEAR.to_owned(),
            copyright_holder: DEFAULT_COPYRIGHT_HOLDER.to_owned(),
            working_dir: None,
            autogenerate: false,
            development_mode: false,
            issuer: None,
            public_path_prefix: String::new(),
            public_http_enabled: true,
            public_http_addr: None,
            public_grpc_enabled: true,
            public_grpc_addr: None,
            telemetry_addr: None,
            admin_addr: None,
            admin_allow: Vec::new(),
            disclose_build: true,
            error_detail: None,
            log_level: LogLevel::default(),
            log_format: LogFormat::default(),
            public_tls: None,
            admin_tls: None,
            telemetry_tls: None,
            tls_reload: true,
            tls_reload_interval: DEFAULT_TLS_RELOAD_INTERVAL,
            limits: Limits::default(),
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            secrets_provider: SecretProvider::None,
            secrets_directory: None,
            secrets_env_prefix: "PERMGUARD_SECRET".to_owned(),
            audit_destination: AuditDestination::default(),
            audit_refusals: false,
            notp_max_batch_bytes: DEFAULT_NOTP_MAX_BATCH_BYTES,
            notp_compression: DEFAULT_NOTP_COMPRESSION,
            mirrors_enabled: false,
            gc_enabled: DEFAULT_GC_ENABLED,
            gc_interval: DEFAULT_GC_INTERVAL,
            gc_grace: DEFAULT_GC_GRACE,
            authz_cache_partitions: DEFAULT_AUTHZ_CACHE_PARTITIONS,
            authz_cache_bytes: DEFAULT_AUTHZ_CACHE_BYTES,
            authz_max_evaluations: DEFAULT_AUTHZ_MAX_EVALUATIONS,
            max_blocking: DEFAULT_MAX_BLOCKING,
            log_enabled: false,
            log_pdp_id: String::new(),
            log_spool_directory: DEFAULT_LOG_SPOOL_DIRECTORY.to_owned(),
            log_spool_bytes: DEFAULT_LOG_SPOOL_BYTES,
            events_enabled: false,
            events_producer_id: String::new(),
            events_directory: DEFAULT_EVENTS_DIRECTORY.to_owned(),
            events_max_bytes: DEFAULT_EVENTS_MAX_BYTES,
            events_segment_bytes: DEFAULT_EVENTS_SEGMENT_BYTES,
            events_max_record_bytes: DEFAULT_EVENTS_MAX_RECORD_BYTES,
            events_retention_minimum: DEFAULT_EVENTS_RETENTION_MINIMUM,
            events_allowed_lateness: DEFAULT_EVENTS_ALLOWED_LATENESS,
            events_clock_skew: DEFAULT_EVENTS_CLOCK_SKEW,
            events_group_commit_delay: DEFAULT_EVENTS_GROUP_COMMIT_DELAY,
            events_pull_mode: Consistency::Local,
            events_pull_interval: DEFAULT_EVENTS_PULL_INTERVAL,
            events_pull_max_staleness: DEFAULT_EVENTS_PULL_MAX_STALENESS,
            experimental: BTreeMap::new(),
            events_pull_ledgers: Vec::new(),
            events_pull_producer_keys: Vec::new(),
            log_spool_age: DEFAULT_LOG_SPOOL_AGE,
            log_batch_bytes: DEFAULT_LOG_BATCH_BYTES,
            log_batch_interval: DEFAULT_LOG_BATCH_INTERVAL,
            log_on_full_open: true,
            log_sample_permits: DEFAULT_LOG_SAMPLE_PERMITS,
            log_commitment_key_ref: None,
            log_commitment_key_version: DEFAULT_KEY_VERSION.to_owned(),
            log_destination: None,
            events_destination: None,
            log_include: crate::decisions::IncludeSection::default(),
            decision_store_enabled: false,
            decision_store_directory: DEFAULT_DECISION_STORE_DIRECTORY.to_owned(),
            event_store_enabled: false,
            event_store_directory: DEFAULT_EVENT_STORE_DIRECTORY.to_owned(),
            event_store_retention: DEFAULT_EVENT_STORE_RETENTION,
            decision_store_retention: DEFAULT_DECISION_STORE_RETENTION,
            decision_producer_keys: Vec::new(),
            event_producer_keys: Vec::new(),
            mirrors_interval: DEFAULT_MIRRORS_INTERVAL,
            mirrors_timeout: DEFAULT_MIRRORS_TIMEOUT,
            mirrors_parallelism: DEFAULT_MIRRORS_PARALLELISM,
            mirrors_jitter: DEFAULT_MIRRORS_JITTER,
            mirrors_stale_after: None,
            mirrors_expire_after: None,
            mirror_sources: Vec::new(),
            otel_enabled: false,
            otel_endpoint: DEFAULT_OTEL_ENDPOINT.to_owned(),
            otel_sample_rate: DEFAULT_OTEL_SAMPLE_RATE,
            notp_max_batch_objects: DEFAULT_NOTP_MAX_BATCH_OBJECTS,
            notp_max_push_objects: DEFAULT_NOTP_MAX_PUSH_OBJECTS,
            notp_max_push_bytes: DEFAULT_NOTP_MAX_PUSH_BYTES,
            notp_ledger_quota_bytes: DEFAULT_NOTP_LEDGER_QUOTA_BYTES,
            audit_directory: None,
            audit_retention: DEFAULT_AUDIT_RETENTION,
            audit_pseudonym_enabled: false,
            audit_pseudonym_key_ref: None,
            audit_pseudonym_key_version: DEFAULT_KEY_VERSION.to_owned(),
            keys_enabled: false,
            keys_directory: None,
            control_keys_enabled: None,
            control_keys_directory: None,
            data_keys_enabled: None,
            data_keys_directory: None,
            keys_publish_ahead: DEFAULT_KEYS_PUBLISH_AHEAD,
            keys_rotate_every: DEFAULT_KEYS_ROTATE_EVERY,
            keys_retain: DEFAULT_KEYS_RETAIN,
            keys_maintenance_interval: DEFAULT_KEYS_MAINTENANCE_INTERVAL,
            keys_lifecycle_declared: BTreeSet::new(),
            realms: Vec::new(),
            declared: BTreeSet::new(),
            declared_values: BTreeMap::new(),
            sections: BTreeMap::new(),
        }
    }
}

impl Config {
    /// Builds the config from all precedence layers.
    ///
    /// Later layers overwrite only settings they actually contain:
    ///
    /// 1. typed defaults;
    /// 2. build metadata;
    /// 3. the configuration file;
    /// 4. the runtime environment;
    /// 5. command-line inputs.
    ///
    /// # Why the environment beats the file
    ///
    /// Because of where each one comes from. A configuration file is written once and travels with
    /// the build — baked into a container image, checked into a chart, copied between environments —
    /// so it describes the *product*. The environment is set by whoever is running this particular
    /// instance, so it describes the *deployment*. When the two disagree, the deployment is the one
    /// that knows something the file could not.
    ///
    /// It is also what every other tool does, and being the exception costs more than it is worth:
    /// an operator who sets `PERMGUARD_LOG_LEVEL` and sees no change does not think "interesting
    /// precedence choice", they think the setting is broken.
    ///
    /// `declared_settings` names the extra keys this build understands on top of the typed ones.
    ///
    /// A value a layer cannot be read as its type is an error rather than a silent fallback: a build
    /// asked for `debug` and given `verbose` should say so, not quietly log less than it was told to.
    pub fn from_layers<D, S>(
        build_settings: BuildSettings,
        declared_settings: D,
        layers: Layers,
    ) -> Result<Self>
    where
        D: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut config = Self {
            declared: declared_settings.into_iter().map(Into::into).collect(),
            ..Self::default()
        };

        config.apply_build_settings(build_settings);
        config.apply_pairs(layers.file)?;
        config.apply_pairs(layers.environment)?;
        config.apply_pairs(layers.command_line)?;

        Ok(config)
    }

    /// Attaches the servers this plane mirrors, as the configuration file declared them.
    ///
    /// Structured, so it comes from the file only — the same reason realms do. Each source is
    /// checked for shape here, at startup: a URL that is not a URL should stop a deployment while
    /// somebody is watching, not surprise a mirror an hour later.
    pub fn with_mirror_sources(
        mut self,
        sources: impl IntoIterator<Item = crate::mirrors::MirrorSource>,
    ) -> Result<Self> {
        self.mirror_sources = sources.into_iter().collect();
        for source in &self.mirror_sources {
            crate::mirrors::check_source(source)?;
        }

        Ok(self)
    }

    /// Attaches the realms this deployment hosts, resolved from the configuration file.
    ///
    /// Separate from the layered settings above on purpose: a realm is a structured record, not a
    /// flat key, and it comes only from the file (and, later, a database). There is no sensible way to
    /// set an array of realms from a single environment variable, so it does not ride that pipeline.
    pub fn with_realms(mut self, realms: impl IntoIterator<Item = RealmInput>) -> Result<Self> {
        self.realms = realms
            .into_iter()
            .map(|input| self.resolve_realm(input))
            .collect::<Result<Vec<_>>>()?;

        Ok(self)
    }

    /// Resolves one realm's declared overrides against the server's values.
    ///
    /// This is the one place base ⊕ override happens: every field the realm did not state takes the
    /// server's, parsed with the very same rules the server settings use — so `90d` means the same
    /// thing in a realm as it does at the top level, and an unreadable value is refused here rather
    /// than surprising something downstream. Every field it *did* state is parsed and takes over.
    fn resolve_realm(&self, input: RealmInput) -> Result<RealmConfig> {
        let name = input.name;
        let mount_path = format!("/realms/{name}");

        let listed = match input.listed {
            Some(value) => parse_bool(&value)
                .with_context(|| format!("reading `listed` for the realm `{name}`"))?,
            None => false,
        };

        let inherit_bool = |value: Option<String>, server: bool, field: &str| -> Result<bool> {
            match value {
                Some(value) => parse_bool(&value)
                    .with_context(|| format!("reading `{field}` for the realm `{name}`")),
                None => Ok(server),
            }
        };
        let inherit_duration =
            |value: Option<String>, server: Duration, field: &str| -> Result<Duration> {
                match value {
                    Some(value) => parse_duration(&value)
                        .with_context(|| format!("reading `{field}` for the realm `{name}`")),
                    None => Ok(server),
                }
            };

        let secrets_provider = match input.secrets_provider {
            Some(value) => value
                .parse()
                .with_context(|| format!("reading the secrets provider for the realm `{name}`"))?,
            None => self.secrets_provider,
        };
        let audit_destination = match input.audit_sink {
            Some(value) => value
                .parse()
                .with_context(|| format!("reading the audit sink for the realm `{name}`"))?,
            None => self.audit_destination,
        };

        // A realm's issuer defaults to the deployment's public base plus its path; an explicit issuer
        // on the realm overrides. With no base configured it stays `None`, and URLs fall back to the
        // realm's mount path.
        let issuer = input.issuer.or_else(|| {
            self.issuer()
                .map(|base| format!("{}/realms/{name}", base.trim_end_matches('/')))
        });

        // The token ring is on by default — a realm is an issuer — but its lifecycle is **not**
        // inherited from anything: signing-key policy is security, so a realm that signs tokens must
        // state its own `keys` block explicitly. It does not borrow the operations cadence, which
        // rotates a *different* key for a *different* purpose.
        let token_keys_enabled = match input.token_keys_enabled {
            Some(value) => parse_bool(&value)
                .with_context(|| format!("reading `keys.enabled` for the realm `{name}`"))?,
            None => true,
        };
        let require_token = |value: Option<String>, field: &str| -> Result<Duration> {
            match value {
                Some(value) => parse_duration(&value)
                    .with_context(|| format!("reading `keys.{field}` for the realm `{name}`")),
                None if !token_keys_enabled => Ok(Duration::ZERO),
                None => bail!(
                    "the realm `{name}` signs tokens but declares no `keys.{field}`: a signing-key \
                     lifecycle has to be stated, this build does not default one. Set the realm's \
                     `keys.publish_ahead`, `keys.rotate_every` and `keys.retain`, or `keys.enabled: \
                     false` if it issues nothing"
                ),
            }
        };
        let token_keys_publish_ahead =
            require_token(input.token_keys_publish_ahead, "publish_ahead")?;
        let token_keys_rotate_every = require_token(input.token_keys_rotate_every, "rotate_every")?;
        let token_keys_retain = require_token(input.token_keys_retain, "retain")?;
        // The lifetime of the authority a realm hands out is not something to default quietly: a
        // realm that issues tokens states it, or the deployment does not start.
        let token_lifetime = match input.token_lifetime {
            Some(value) => parse_duration(&value)
                .with_context(|| format!("the realm `{name}` has an invalid `token_lifetime`"))?,
            None if !token_keys_enabled => Duration::ZERO,
            None => bail!(
                "the realm `{name}` issues tokens but declares no `token_lifetime`: how long issued authority stays valid is a deployment decision, and this build does not default one. Set the realm's `token_lifetime`, or `keys.enabled: false` if it issues nothing"
            ),
        };
        let token_initial_expiry_policy = match input.token_initial_expiry_policy {
            Some(value) => parse_token_initial_expiry_policy(&value).with_context(|| {
                format!("the realm `{name}` has an invalid `token_initial_expiry_policy`")
            })?,
            None => TokenInitialExpiryPolicy::Later,
        };
        let key_cache_stale_for = match input.key_cache_stale_for {
            Some(value) => parse_duration_allow_zero(&value).with_context(|| {
                format!("the realm `{name}` has an invalid `key_cache_stale_for`")
            })?,
            None => Duration::from_secs(3_600),
        };

        // Only the algorithms this build can actually sign with are accepted, and the check happens
        // at startup: a realm that names one it cannot produce would otherwise fail at the first
        // token it is asked for.
        let token_signing_algorithm = match input.token_signing_algorithm.as_deref() {
            None => "EdDSA".to_owned(),
            Some("EdDSA") => "EdDSA".to_owned(),
            Some("ES256") => "ES256".to_owned(),
            Some(other) => bail!(
                "the realm `{name}` names the signing algorithm `{other}`, which this build cannot \
produce: use `EdDSA` or `ES256`"
            ),
        };

        Ok(RealmConfig {
            token_signing_algorithm,
            mount_path,
            issuer,
            listed,
            token_keys_enabled,
            token_keys_publish_ahead,
            token_keys_rotate_every,
            token_keys_retain,
            token_lifetime,
            token_initial_expiry_policy,
            key_cache_stale_for,
            // The operations ring inherits the shared `operations` block unless the realm overrides it.
            operations_keys_enabled: inherit_bool(
                input.operations_keys_enabled,
                self.keys_enabled,
                "operations.keys.enabled",
            )?,
            operations_keys_publish_ahead: inherit_duration(
                input.operations_keys_publish_ahead,
                self.keys_publish_ahead,
                "operations.keys.publish_ahead",
            )?,
            operations_keys_rotate_every: inherit_duration(
                input.operations_keys_rotate_every,
                self.keys_rotate_every,
                "operations.keys.rotate_every",
            )?,
            operations_keys_retain: inherit_duration(
                input.operations_keys_retain,
                self.keys_retain,
                "operations.keys.retain",
            )?,
            audit_destination,
            audit_retention: inherit_duration(
                input.audit_retention,
                self.audit_retention,
                "audit.retention",
            )?,
            audit_pseudonym_enabled: inherit_bool(
                input.audit_pseudonym_enabled,
                self.audit_pseudonym_enabled,
                "audit.pseudonym.enabled",
            )?,
            audit_pseudonym_key_ref: input
                .audit_pseudonym_key_ref
                .map(SecretRef::new)
                .or_else(|| self.audit_pseudonym_key_ref.clone()),
            audit_pseudonym_key_version: input
                .audit_pseudonym_key_version
                .unwrap_or_else(|| self.audit_pseudonym_key_version.clone()),
            secrets_provider,
            secrets_env_prefix: input.secrets_env_prefix.unwrap_or_else(|| {
                // A per-realm environment prefix defaults to the server's, suffixed with the realm, so
                // two realms resolving from the environment cannot collide on the same variable.
                format!(
                    "{}_{}",
                    self.secrets_env_prefix,
                    name.to_uppercase().replace('-', "_")
                )
            }),
            exchange_profiles: input.exchange_profiles,
            trusted_attesters: input.trusted_attesters,
            name,
        })
    }

    /// Checks that the assembled config can actually start a server.
    ///
    /// Validation runs after every layer has been applied, so a command-line override can satisfy a
    /// requirement the configuration file left out.
    pub fn validate(&self) -> Result<()> {
        // Before anything that touches the filesystem: this is a mistake in the configuration's
        // shape, and the message should name it rather than whichever file check fires first.
        if let Some(tls) = self.public_tls.as_ref()
            && !tls.allow().is_empty()
            && tls.client_ca().is_none()
        {
            bail!(
                "the public surface names peers it answers but demands no client certificate: an \
                 allow list with no identity to check is a list nothing can satisfy — set \
                 `public.tls.client_ca`, or remove `public.tls.allow`"
            );
        }

        let declared_addresses = self.declared_addresses()?;

        if self.public_http_addr().is_none()
            && self.public_grpc_addr().is_none()
            && self.declared_extra_addresses()?.is_empty()
        {
            bail!(
                "the configuration defines no public listen address: set `public.http.addr` or \
                 `public.grpc.addr`, configure a plane public address, or pass --public-http-addr"
            );
        }

        for (label, addr) in declared_addresses {
            if addr.trim().is_empty() {
                bail!("the {label} listen address is empty");
            }
        }

        if let Some(issuer) = self.issuer() {
            self.require_public_https(issuer, "issuer")?;
        }

        if !self.public_path_prefix.is_empty() && !self.public_path_prefix.starts_with('/') {
            bail!(
                "the public path prefix {} does not start with a slash",
                self.public_path_prefix
            );
        }

        for (surface, tls) in [
            ("public", self.public_tls.as_ref()),
            ("admin", self.admin_tls.as_ref()),
            ("telemetry", self.telemetry_tls.as_ref()),
        ] {
            if let Some(tls) = tls {
                tls.validate_in(self.working_dir())
                    .with_context(|| format!("validating the {surface} TLS material"))?;
            }
        }

        self.validate_development()?;
        self.validate_admin_access()?;
        self.validate_key_lifecycle()?;
        self.validate_realms()?;

        // Turning pseudonymisation on and leaving the key out is a misconfiguration, not a reason to
        // record less carefully than the deployment asked for. It stops the start.
        if self.audit_pseudonym_enabled {
            if self.secrets_provider == SecretProvider::None {
                bail!(
                    "audit pseudonymisation is enabled but no secret provider is configured: the key \
                     is named by `audit.pseudonym.key_ref` and has to be resolved from somewhere"
                );
            }

            if self.audit_pseudonym_key_ref.is_none() {
                bail!(
                    "audit pseudonymisation is enabled but names no secret: set \
                     `audit.pseudonym.key_ref` to the name of the key in the secret store"
                );
            }

            if self.audit_pseudonym_key_version.trim().is_empty() {
                bail!("the audit pseudonymisation key version is empty");
            }
        }

        Ok(())
    }

    /// Refuses the conveniences of development to a deployment that has not said it is one.
    ///
    /// A server that mints its own certificate authority is trusted by nobody but itself. That is
    /// exactly right on a laptop and never right anywhere else, and the difference must not be one
    /// variable away from being wrong — so it takes two, and the second one is the one an operator
    /// reads in the log and in the banner.
    fn validate_development(&self) -> Result<()> {
        if self.autogenerate && !self.development_mode {
            bail!(
                "generating missing material is only offered in development: set \
                 `development_mode: true` if this is one, or supply the material this deployment is \
                 missing"
            );
        }

        Ok(())
    }

    /// Refuses an administrative surface that anybody can reach and nobody has been named for.
    ///
    /// Mutual TLS answers *was this signed by an authority we trust*. It does not answer *may this
    /// client administer this deployment*, and a surface that stops at the first question hands
    /// administration to every client that authority ever signed — which, for the authority that
    /// also issues ordinary service certificates, is usually all of them.
    fn validate_admin_access(&self) -> Result<()> {
        let Some(address) = self.admin_addr() else {
            return Ok(());
        };

        let mutual = self.admin_tls.as_ref().is_some_and(TlsSettings::is_mutual);

        if !mutual {
            if is_loopback(address) || self.development_mode {
                return Ok(());
            }

            bail!(
                "the administrative surface is bound to {address}, which is reachable from outside \
                 this host, and demands no client certificate: set `admin.tls.client_ca`, bind it to \
                 a loopback address, or say `development_mode: true`"
            );
        }

        if self.admin_allow.is_empty() && !self.development_mode {
            bail!(
                "the administrative surface demands a client certificate but names nobody: list the \
                 peers that may administer it under `admin.allow`, because a certificate authority \
                 signs every client it was built for and mutual TLS alone would admit all of them"
            );
        }

        Ok(())
    }

    /// Refuses a client-facing URL that is not https, outside development.
    ///
    /// An issuer — the server's, and each realm's — is a public identity: it is what a relying party
    /// is told to trust and fetches keys from, and RFC 8414 requires it to use `https`. A plaintext
    /// one is refused rather than warned about, because a downgraded issuer is invisible right up to
    /// the moment a token travels over it in the clear. `development_mode` is the single switch that
    /// relaxes it — the same one every other relaxation is justified against — and loopback is *not*
    /// special-cased: nobody advertises a loopback issuer to real clients, and a local run says
    /// `development_mode: true` anyway.
    ///
    /// The listener is a separate question. A deployment behind an ingress or a service mesh that
    /// terminates TLS serves this issuer over plain http on the wire and is right to — which is why
    /// this checks the URL clients are *told*, never the address the process binds.
    fn require_public_https(&self, url: &str, field: &str) -> Result<()> {
        if self.development_mode || url.starts_with("https://") {
            return Ok(());
        }

        bail!(
            "the {field} {url} is not https: it is a public identity clients are told to trust and \
             fetch their verification keys from, so it must use https (RFC 8414). Put it behind \
             something that terminates TLS and state the https URL here, or say \
             `development_mode: true` for a local run"
        );
    }

    /// Refuses a key lifecycle whose windows do not overlap.
    ///
    /// Both mistakes here are silent for weeks and then break everything at once, which is why they
    /// are checked at startup rather than discovered at the first rotation.
    fn validate_key_lifecycle(&self) -> Result<()> {
        if !self.keys_enabled {
            return Ok(());
        }

        // Signing-key policy is security, so it must be stated, not defaulted: with the operations
        // ring enabled, its lifecycle has to have been declared by some layer.
        for (setting, field) in [
            (SETTING_KEYS_PUBLISH_AHEAD, "publish_ahead"),
            (SETTING_KEYS_ROTATE_EVERY, "rotate_every"),
            (SETTING_KEYS_RETAIN, "retain"),
        ] {
            if !self.keys_lifecycle_declared.contains(setting) {
                bail!(
                    "the operations keys are enabled but `operations.keys.{field}` is not set: a \
                     signing-key lifecycle has to be stated, this build does not default one"
                );
            }
        }

        self.check_key_lifecycle(
            self.keys_publish_ahead,
            self.keys_rotate_every,
            self.keys_retain,
            "the server",
        )
    }

    /// The overlap rules a key lifecycle has to satisfy, for whoever owns it — the server or a realm.
    ///
    /// One place, so a realm's rotation is held to exactly the same arithmetic as the server's; both
    /// mistakes here are silent for weeks and then break everything at once.
    fn check_key_lifecycle(
        &self,
        publish_ahead: Duration,
        rotate_every: Duration,
        retain: Duration,
        who: &str,
    ) -> Result<()> {
        if publish_ahead >= rotate_every {
            bail!(
                "for {who}, a key would be replaced after {rotate_every:?} but is only published \
                 {publish_ahead:?} before it signs: it would never get a turn"
            );
        }

        if retain < rotate_every {
            bail!(
                "for {who}, a retired key is kept for {retain:?} but keys are replaced every \
                 {rotate_every:?}, which leaves signatures made in between with no published key to \
                 verify against"
            );
        }

        // The half of the pair that is easy to miss: a verifier is told it may keep the key set for
        // `KEY_SET_MAX_AGE`, so a key that starts signing sooner than that is verified against a set
        // that does not contain it. Development wants short windows to watch a rotation happen, and
        // has no verifiers to break.
        if publish_ahead < KEY_SET_MAX_AGE && !self.development_mode {
            bail!(
                "for {who}, a key would start signing {publish_ahead:?} after it is published, but \
                 the key set is served with a cache of {KEY_SET_MAX_AGE:?}: every verifier holding a \
                 cached copy would reject the signatures made in between. Publish it at least \
                 {KEY_SET_MAX_AGE:?} ahead"
            );
        }

        Ok(())
    }

    /// Refuses a set of realms that cannot be told apart or safely mounted.
    ///
    /// A realm's name becomes a URL path segment and a directory on disk, so it is checked against
    /// both roles at once: lowercase letters, digits and internal hyphens, nothing that could climb
    /// out of the volume (`..`, a slash) or produce a surprising URL. And two realms with the same
    /// name are refused rather than silently collapsed into one — which key would sign, which trail
    /// would record, is not a question to answer by insertion order.
    fn validate_realms(&self) -> Result<()> {
        let mut seen = BTreeSet::new();

        for realm in &self.realms {
            let name = realm.name();

            if !seen.insert(name.to_owned()) {
                bail!(
                    "two realms are named `{name}`: a realm name has to be unique, because it is what \
                     decides whose keys sign and whose trail records"
                );
            }

            let shaped = !name.is_empty()
                && name.len() <= 40
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !name.starts_with('-')
                && !name.ends_with('-');

            if !shaped {
                bail!(
                    "the realm name `{name}` is not usable: a name becomes a URL path and a directory, \
                     so it must be 1 to 40 characters of lowercase letters, digits and internal \
                     hyphens — nothing else"
                );
            }

            // A realm's issuer is a public identity too — an explicit one it set for its own host,
            // or one derived from the deployment's public URL — so it is held to the same https rule.
            if let Some(issuer) = realm.issuer() {
                self.require_public_https(issuer, &format!("issuer of the realm `{name}`"))?;
            }

            // Both of a realm's rings are held to the same overlap rules as the server's — an override
            // does not buy an exemption from arithmetic that would strand its own signatures.
            if realm.operations_keys_enabled {
                self.check_key_lifecycle(
                    realm.operations_keys_publish_ahead,
                    realm.operations_keys_rotate_every,
                    realm.operations_keys_retain,
                    &format!("the operations ring of the realm `{name}`"),
                )?;
            }
            if realm.token_keys_enabled {
                self.check_key_lifecycle(
                    realm.token_keys_publish_ahead,
                    realm.token_keys_rotate_every,
                    realm.token_keys_retain,
                    &format!("the token ring of the realm `{name}`"),
                )?;
            }

            // Pseudonymisation a realm turned on has to have somewhere to resolve its key from and a
            // name to resolve — the same requirement the server has, checked per realm because a
            // realm can enable it when the server did not.
            if realm.audit_pseudonym_enabled {
                if realm.secrets_provider == SecretProvider::None {
                    bail!(
                        "the realm `{name}` enables audit pseudonymisation but resolves secrets from \
                         nowhere: give it a `secrets.provider`, or turn its pseudonymisation off"
                    );
                }

                if realm.audit_pseudonym_key_ref.is_none() {
                    bail!(
                        "the realm `{name}` enables audit pseudonymisation but names no secret: set \
                         `audit.pseudonym.key_ref`"
                    );
                }
            }

            self.validate_exchange_profiles(realm.exchange_profiles(), name)?;
            self.validate_trusted_attesters(realm.trusted_attesters(), name)?;
        }

        Ok(())
    }

    /// Refuses attestation issuer metadata that cannot be published or used safely later.
    fn validate_trusted_attesters(
        &self,
        attesters: &[TrustedAttesterConfig],
        realm: &str,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();

        for attester in attesters {
            let id = attester.id.trim();
            if id.is_empty() {
                bail!("the realm `{realm}` declares an attester with an empty id");
            }
            if !seen.insert(id.to_owned()) {
                bail!("the realm `{realm}` declares the attester `{id}` twice");
            }
            if attester.issuer.trim().is_empty() {
                bail!("the attester `{id}` in realm `{realm}` has an empty issuer");
            }
            if attester.jwks_uri.trim().is_empty() {
                bail!("the attester `{id}` in realm `{realm}` has an empty jwks_uri");
            }
            self.require_public_https(
                &attester.issuer,
                &format!("issuer of attester `{id}` in realm `{realm}`"),
            )?;
            self.require_public_https(
                &attester.jwks_uri,
                &format!("jwks_uri of attester `{id}` in realm `{realm}`"),
            )?;
            if attester.proof_types.is_empty() {
                bail!("the attester `{id}` in realm `{realm}` declares no proof types");
            }
            if !attester.proof_types.iter().any(|value| value == "sd-jwt") {
                bail!(
                    "the attester `{id}` in realm `{realm}` does not support Profile 0.2 proof type `sd-jwt`"
                );
            }
            if attester.formats.is_empty() {
                bail!("the attester `{id}` in realm `{realm}` declares no formats");
            }
            if !attester.formats.iter().any(|value| value == "sd-jwt") {
                bail!(
                    "the attester `{id}` in realm `{realm}` does not publish Profile 0.2 format `sd-jwt`"
                );
            }
        }

        Ok(())
    }

    /// Refuses Exchange Profiles whose stated validation or mapping cannot be applied safely.
    fn validate_exchange_profiles(
        &self,
        profiles: &[ExchangeProfileConfig],
        realm: &str,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();

        for profile in profiles {
            let id = profile.id.trim();
            if id.is_empty() {
                bail!("the realm `{realm}` declares an exchange profile with an empty id");
            }
            if !seen.insert(id.to_owned()) {
                bail!("the realm `{realm}` declares the exchange profile `{id}` twice");
            }

            if profile.source.token_type != EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` has unsupported source token \
                     type `{}`; this build supports `{EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN}` for \
                     initialization",
                    profile.source.token_type
                );
            }
            if profile.source.format != EXCHANGE_SOURCE_FORMAT_JWT {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` has unsupported source format \
                     `{}`; this build supports `{EXCHANGE_SOURCE_FORMAT_JWT}`",
                    profile.source.format
                );
            }
            if profile.source.issuer.trim().is_empty() {
                bail!("the exchange profile `{id}` in realm `{realm}` has an empty source issuer");
            }
            if profile.source.audience.trim().is_empty() {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` has an empty source audience"
                );
            }
            if profile.source.validation.allowed_algorithms.is_empty() {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` declares no allowed source JWT \
                     algorithms"
                );
            }
            if !profile.source.validation.require_expiration {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` must require expiration on \
                     incoming access tokens"
                );
            }
            if profile
                .source
                .validation
                .require_token_type
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` must require an explicit source \
                     JWT `typ`"
                );
            }

            for (claim, mapping) in &profile.claims.identity_context {
                let has_from = mapping
                    .from
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty());
                let has_value = mapping
                    .value
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty());
                if has_from == has_value {
                    bail!(
                        "the identity-context mapping `{claim}` in exchange profile `{id}` of realm \
                         `{realm}` must declare exactly one of `from` or `value`"
                    );
                }
            }

            if profile
                .claims
                .scopes
                .from
                .as_deref()
                .is_none_or(|value| value.is_empty())
            {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` must map `claims.scopes.from`"
                );
            }
            if profile.claims.scopes.value_type.as_deref() != Some("set") {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` must map `claims.scopes.type: set`"
                );
            }
            if profile.privileges.source != "scopes" {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` has unsupported privileges source \
                     `{}`; use `scopes`",
                    profile.privileges.source
                );
            }
            if profile.privileges.rules.is_empty() {
                bail!("the exchange profile `{id}` in realm `{realm}` declares no privilege rules");
            }

            let mut priorities = BTreeSet::new();
            let mut names = BTreeSet::new();
            for rule in &profile.privileges.rules {
                if rule.name.trim().is_empty() {
                    bail!(
                        "an exchange profile rule in `{id}` of realm `{realm}` has an empty name"
                    );
                }
                if !names.insert(rule.name.as_str()) {
                    bail!(
                        "the exchange profile `{id}` in realm `{realm}` declares rule `{}` twice",
                        rule.name
                    );
                }
                if !priorities.insert(rule.priority) {
                    bail!(
                        "the exchange profile `{id}` in realm `{realm}` reuses priority {}; rules \
                         with equal priority have unspecified order",
                        rule.priority
                    );
                }
                if rule.pattern.trim().is_empty() {
                    bail!(
                        "the exchange profile `{id}` in realm `{realm}` has an empty pattern for \
                         rule `{}`",
                        rule.name
                    );
                }
                for (field, template) in [
                    ("scope", &rule.emit.scope),
                    ("operation", &rule.emit.operation),
                    ("resource_type", &rule.emit.resource_type),
                    ("resource_id", &rule.emit.resource_id),
                ] {
                    if template.trim().is_empty() {
                        bail!(
                            "the exchange profile `{id}` in realm `{realm}` emits an empty `{field}` \
                             from rule `{}`",
                            rule.name
                        );
                    }
                }
            }

            if profile.on_unmatched_scope != EXCHANGE_ON_UNMATCHED_SCOPE_REJECT {
                bail!(
                    "the exchange profile `{id}` in realm `{realm}` has unsupported \
                     on_unmatched_scope `{}`; use `{EXCHANGE_ON_UNMATCHED_SCOPE_REJECT}`",
                    profile.on_unmatched_scope
                );
            }
        }

        Ok(())
    }

    /// Returns the effective product version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the commit the running binary was built from, or `unknown`.
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// Returns the effective copyright year.
    pub fn copyright_year(&self) -> &str {
        &self.copyright_year
    }

    /// Returns the effective copyright holder.
    pub fn copyright_holder(&self) -> &str {
        &self.copyright_holder
    }

    /// Returns the directory this deployment keeps everything in.
    pub fn working_dir(&self) -> &Path {
        self.working_dir
            .as_deref()
            .map_or_else(|| Path::new(DEFAULT_WORKING_DIR), Path::new)
    }

    /// Resolves `path` against the working directory, leaving absolute paths alone.
    pub fn resolve(&self, path: impl AsRef<Path>) -> PathBuf {
        let path = path.as_ref();

        if path.is_absolute() {
            return path.to_path_buf();
        }

        self.working_dir().join(path)
    }

    /// Reports whether the server may create material it was not given.
    ///
    /// False unless a deployment says otherwise, and deliberately so. A server that can mint its own
    /// certificate authority is a server whose trust nobody vouched for, and the difference between
    /// development and production must not be one variable away from being wrong. Development turns
    /// it on explicitly; nothing turns it on by accident.
    pub fn autogenerate(&self) -> bool {
        self.autogenerate
    }

    /// Reports whether this deployment has said it is somebody's laptop.
    ///
    /// Nothing reads this to decide whether something is *possible*. It decides whether a
    /// configuration that would be indefensible in production is refused or merely complained about
    /// — and every place that consults it says so in its own message, so an operator reading a log
    /// can tell which of the two they are running.
    pub fn development_mode(&self) -> bool {
        self.development_mode
    }

    /// Returns the peers the administrative surface answers, in the order they were listed.
    ///
    /// Empty is a real answer and not a missing one: it means nobody is on the list, which
    /// [`Config::validate`] refuses outside development because mutual TLS on its own authorises
    /// every client the authority ever signed.
    pub fn admin_allow(&self) -> &[AllowedPeer] {
        &self.admin_allow
    }

    /// Returns whether the public surface says which build it is.
    pub fn disclose_build(&self) -> bool {
        self.disclose_build
    }

    /// Returns how much an error on the wire says about the inside.
    ///
    /// Explicit configuration wins; without one, a development workstation gets the detail and
    /// everything else gets the safe minimum.
    pub fn error_detail(&self) -> Disclosure {
        self.error_detail.unwrap_or(if self.development_mode {
            Disclosure::Full
        } else {
            Disclosure::Minimal
        })
    }

    /// Reports whether transport material is re-read while the server runs.
    pub fn tls_reload(&self) -> bool {
        self.tls_reload
    }

    /// Returns how often transport material is re-read.
    pub fn tls_reload_interval(&self) -> Duration {
        self.tls_reload_interval
    }

    /// Returns what every surface refuses to spend on any one client.
    pub fn limits(&self) -> Limits {
        self.limits.clone()
    }

    /// Returns the public URL this deployment is reached at, when one is configured.
    ///
    /// This is what clients are told, not what the process binds. A deployment behind a reverse proxy
    /// is reached at a name and possibly a path that the process itself never sees, and no header a
    /// proxy sets is trustworthy enough to derive it from — so it is stated, not inferred.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Returns the path the public surface is mounted under, empty when it is mounted at the root.
    ///
    /// Almost always empty. A proxy that serves this deployment under a path strips that path before
    /// forwarding, which is one line of proxy configuration and leaves the process serving the root.
    /// This exists for the proxies that do not strip, and setting it is a deliberate act.
    pub fn public_path_prefix(&self) -> &str {
        &self.public_path_prefix
    }

    /// Returns the absolute URL a client should use for `path`, when an issuer says what that is.
    ///
    /// Without an issuer the answer is the path itself: a deployment nobody told the public name of
    /// cannot invent one, and a relative reference is at least never wrong.
    pub fn public_url(&self, path: &str) -> String {
        match self.issuer() {
            Some(issuer) => format!("{}{path}", issuer.trim_end_matches('/')),
            None => path.to_owned(),
        }
    }

    /// Returns the effective public HTTP listen address, when one is configured.
    pub fn public_http_addr(&self) -> Option<&str> {
        self.public_http_enabled
            .then_some(self.public_http_addr.as_deref())
            .flatten()
    }

    /// Returns the effective public gRPC listen address, when one is configured.
    pub fn public_grpc_addr(&self) -> Option<&str> {
        self.public_grpc_enabled
            .then_some({
                self.public_grpc_addr
                    .as_deref()
                    .or(self.public_http_addr.as_deref())
            })
            .flatten()
    }

    /// Returns the effective telemetry listen address, when one is configured.
    pub fn telemetry_addr(&self) -> Option<&str> {
        self.telemetry_addr.as_deref()
    }

    /// Returns the effective admin listen address, when one is configured.
    pub fn admin_addr(&self) -> Option<&str> {
        self.admin_addr.as_deref()
    }

    /// Returns how much this build says.
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Returns the shape this build writes its records in.
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }

    /// Returns the TLS material of the public surface, with its paths already resolved.
    pub fn public_tls(&self) -> Option<TlsSettings> {
        self.resolved_tls(self.public_tls.as_ref())
    }

    /// Returns the TLS material of the administrative surface, with its paths already resolved.
    pub fn admin_tls(&self) -> Option<TlsSettings> {
        self.resolved_tls(self.admin_tls.as_ref())
    }

    /// Returns the TLS material of the telemetry surface, with its paths already resolved.
    pub fn telemetry_tls(&self) -> Option<TlsSettings> {
        self.resolved_tls(self.telemetry_tls.as_ref())
    }

    /// Resolves whatever paths a surface's material names against the volume, and attaches the
    /// reload policy the deployment asked for.
    ///
    /// Both happen here so that no surface has to remember either. A listener that resolved its own
    /// paths would find them relative to whatever directory the process started in, and one that had
    /// to opt into reloading would be one renewal away from serving an expired certificate.
    fn resolved_tls(&self, settings: Option<&TlsSettings>) -> Option<TlsSettings> {
        settings.map(|settings| {
            let resolved = settings.resolved_in(self.working_dir());

            if self.tls_reload {
                resolved.with_reload(self.tls_reload_interval)
            } else {
                resolved.without_reload()
            }
        })
    }

    /// Returns how long shutdown is given before the process exits anyway.
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Keeps a parsed section a build added, replacing any section of the same type.
    ///
    /// Validation is the caller's business and happens before this point, so a config that holds a
    /// section holds one that was already found to make sense.
    pub fn with_section<T: ConfigSection>(mut self, section: T) -> Self {
        self.sections.insert(T::NAME, Arc::new(section));

        self
    }

    /// Returns the section of type `T`, when the configuration file declared one.
    ///
    /// Reads back as `None` for a build that registered the section but a file that did not declare
    /// it, which is what lets a capability decide whether it was asked for at all.
    pub fn section<T: ConfigSection>(&self) -> Option<&T> {
        self.sections
            .get(T::NAME)
            .and_then(|section| section.as_any().downcast_ref::<T>())
    }

    /// Returns the names of the sections this configuration is carrying.
    pub fn section_names(&self) -> impl Iterator<Item = &'static str> {
        self.sections.keys().copied()
    }

    /// Returns where secrets are resolved from.
    pub fn secrets_provider(&self) -> SecretProvider {
        self.secrets_provider
    }

    /// Returns the directory the `directory` provider reads.
    ///
    /// Relative to the volume unless a deployment names an absolute path, and `secrets` inside it
    /// when nothing is said — which is where provisioning puts them.
    pub fn secrets_directory(&self) -> PathBuf {
        self.resolve(
            self.secrets_directory
                .as_deref()
                .unwrap_or(DEFAULT_SECRETS_SUBDIRECTORY),
        )
    }

    /// Returns the variable prefix the `environment` provider reads.
    pub fn secrets_env_prefix(&self) -> &str {
        &self.secrets_env_prefix
    }

    /// Reports whether audit subjects are pseudonymised.
    pub fn audit_pseudonym_enabled(&self) -> bool {
        self.audit_pseudonym_enabled
    }

    /// Returns the secret the pseudonymisation key is resolved from.
    ///
    /// A reference is not sensitive: it names the material without carrying it, so unlike the key it
    /// replaced it may appear in a log, a diagnostic, or a bug report.
    pub fn audit_pseudonym_key_ref(&self) -> Option<&SecretRef> {
        self.audit_pseudonym_key_ref.as_ref()
    }

    /// Returns the key version every pseudonym names.
    ///
    /// Rotating means changing the key and this version together: the version is what lets a later
    /// question about an older record know which key to recompute with.
    pub fn audit_pseudonym_key_version(&self) -> &str {
        &self.audit_pseudonym_key_version
    }

    /// Returns where the audit trail is written.
    /// Reports whether refused operations are recorded in the trail as well as the log.
    pub fn audit_refusals(&self) -> bool {
        self.audit_refusals
    }

    pub fn audit_destination(&self) -> AuditDestination {
        self.audit_destination
    }

    /// Returns the directory the file sink writes to, resolved against the volume.
    pub fn audit_directory(&self) -> PathBuf {
        self.resolve(
            self.audit_directory
                .as_deref()
                .unwrap_or(DEFAULT_AUDIT_SUBDIRECTORY),
        )
    }

    /// Returns how long a day of audit records is kept.
    pub fn audit_retention(&self) -> Duration {
        self.audit_retention
    }

    /// Returns the largest NOTP transfer batch, in bytes.
    pub fn notp_max_batch_bytes(&self) -> u64 {
        self.notp_max_batch_bytes
    }

    /// Whether NOTP batches are deflate-compressed on the wire.
    pub fn notp_compression(&self) -> bool {
        self.notp_compression
    }

    /// Whether this plane mirrors ledgers at all.
    pub fn mirrors_enabled(&self) -> bool {
        self.mirrors_enabled
    }

    /// Whether the store sweeps objects nothing references.
    pub fn gc_enabled(&self) -> bool {
        self.gc_enabled
    }

    /// How often it sweeps.
    pub fn gc_interval(&self) -> Duration {
        self.gc_interval
    }

    /// How old an unreachable object must be before it may be removed.
    pub fn gc_grace(&self) -> Duration {
        self.gc_grace
    }

    /// Whether this plane records the decisions it answers.
    pub fn log_enabled(&self) -> bool {
        self.log_enabled
    }

    /// This plane's name in the log — half of every stream identity.
    pub fn log_pdp_id(&self) -> &str {
        &self.log_pdp_id
    }

    /// Where the durable local record lives, under the working directory.
    pub fn log_spool_directory(&self) -> &str {
        &self.log_spool_directory
    }

    /// How many bytes of decision records the spool may hold.
    pub fn log_spool_bytes(&self) -> u64 {
        self.log_spool_bytes
    }

    /// Whether this plane serves the temporal interface at all.
    pub fn events_enabled(&self) -> bool {
        self.events_enabled
    }

    /// Whether this control plane receives and serves an event store.
    pub fn event_store_enabled(&self) -> bool {
        self.event_store_enabled
    }

    /// Where the event store keeps what it receives.
    pub fn event_store_directory(&self) -> PathBuf {
        self.working_dir().join(&self.event_store_directory)
    }

    /// How long a tenant's events are kept before sealed segments are dropped.
    pub fn event_store_retention(&self) -> Duration {
        self.event_store_retention
    }

    /// This plane's name as an event producer — the identity its hash chains are owned by.
    pub fn events_producer_id(&self) -> &str {
        &self.events_producer_id
    }

    /// Where this plane keeps its event journals: `<volume>/data/events` unless told otherwise.
    pub fn events_directory(&self) -> PathBuf {
        self.working_dir().join(&self.events_directory)
    }

    /// The bound on one ledger's event records.
    pub fn events_max_bytes(&self) -> u64 {
        self.events_max_bytes
    }

    /// When a journal segment is closed and a new one started.
    pub fn events_segment_bytes(&self) -> u64 {
        self.events_segment_bytes
    }

    /// The largest single event record a journal accepts.
    pub fn events_max_record_bytes(&self) -> u64 {
        self.events_max_record_bytes
    }

    /// The shortest history this deployment promises, before the policies' own requirement.
    pub fn events_retention_minimum(&self) -> Duration {
        self.events_retention_minimum
    }

    /// How late an occurrence may arrive and still be recorded.
    pub fn events_allowed_lateness(&self) -> Duration {
        self.events_allowed_lateness
    }

    /// How far a caller's clock may run ahead of this one.
    pub fn events_clock_skew(&self) -> Duration {
        self.events_clock_skew
    }

    /// How long a group commit may wait to amortise an `fsync` across a batch.
    pub fn events_group_commit_delay(&self) -> Duration {
        self.events_group_commit_delay
    }

    /// Which history this plane's decisions range over.
    pub fn events_pull_mode(&self) -> Consistency {
        self.events_pull_mode
    }

    /// How often the pull worker asks the control plane for more.
    pub fn events_pull_interval(&self) -> Duration {
        self.events_pull_interval
    }

    /// How stale imported history may be before `shared-bounded` fails decisions closed.
    pub fn events_pull_max_staleness(&self) -> Duration {
        self.events_pull_max_staleness
    }

    /// Whether this deployment has opted into the experimental runtime `name`.
    ///
    /// Absent means no. A provisional runtime is served because a deployment said so, never because
    /// the build happens to carry it.
    pub fn experimental_enabled(&self, name: &str) -> bool {
        self.experimental.get(name).copied().unwrap_or(false)
    }

    /// Every experimental runtime this deployment has turned on, by name.
    pub fn experimental_enabled_names(&self) -> impl Iterator<Item = &str> {
        self.experimental
            .iter()
            .filter(|(_, on)| **on)
            .map(|(name, _)| name.as_str())
    }

    /// Every `experimental.<name>` this configuration mentions, on or off.
    ///
    /// What a deployment *named*, which is not what it enabled: naming a runtime this build does
    /// not carry is a typo worth reporting, and the startup check needs to see it to report it.
    pub fn experimental_named(&self) -> impl Iterator<Item = (&str, bool)> {
        self.experimental
            .iter()
            .map(|(name, on)| (name.as_str(), *on))
    }

    /// Whether this deployment will serve Dogwood partitions.
    pub fn experimental_dogwood(&self) -> bool {
        self.experimental_enabled(EXPERIMENTAL_DOGWOOD)
    }

    /// The ledgers this plane imports history from.
    pub fn events_pull_ledgers(&self) -> &[PullSubscription] {
        &self.events_pull_ledgers
    }

    /// Producer keys accepted on history imported by this data plane.
    pub fn events_pull_producer_keys(&self) -> &[crate::decisions::EventProducerSource] {
        &self.events_pull_producer_keys
    }

    /// Records which ledgers this plane subscribes to.
    ///
    /// Structured, so it comes from the file rather than the layered pipeline — a list of
    /// three-part subscriptions has no single-variable form that is not a parser.
    pub fn with_pull_ledgers(mut self, ledgers: Vec<PullSubscription>) -> Self {
        self.events_pull_ledgers = ledgers;

        self
    }

    pub fn with_pull_producer_keys(
        mut self,
        keys: impl IntoIterator<Item = crate::decisions::EventProducerSource>,
    ) -> Self {
        self.events_pull_producer_keys = keys.into_iter().collect();

        self
    }

    /// How old the oldest unshipped record may be.
    pub fn log_spool_age(&self) -> Duration {
        self.log_spool_age
    }

    /// How large a batch may grow before it ships.
    pub fn log_batch_bytes(&self) -> u64 {
        self.log_batch_bytes
    }

    /// How long a batch may wait before it ships anyway.
    pub fn log_batch_interval(&self) -> Duration {
        self.log_batch_interval
    }

    /// Whether a full spool keeps answering (`open`) or refuses (`closed`).
    pub fn log_on_full_open(&self) -> bool {
        self.log_on_full_open
    }

    /// The rate at which permits are recorded. Denies and errors always are.
    pub fn log_sample_permits(&self) -> f64 {
        self.log_sample_permits
    }

    /// Which secret input commitments are taken under.
    pub fn log_commitment_key_ref(&self) -> Option<&SecretRef> {
        self.log_commitment_key_ref.as_ref()
    }

    /// Which version of it, recorded in every marker.
    pub fn log_commitment_key_version(&self) -> &str {
        &self.log_commitment_key_version
    }

    /// Where records are shipped, when the file names a server.
    pub fn log_destination(&self) -> Option<&crate::decisions::LogDestination> {
        self.log_destination.as_ref()
    }

    /// Where event records are shipped and shared history is read from, when named separately.
    pub fn events_destination(&self) -> Option<&crate::decisions::EventDestination> {
        self.events_destination.as_ref()
    }

    /// Which caller-supplied attributes this plane may record.
    pub fn log_include(&self) -> &crate::decisions::IncludeSection {
        &self.log_include
    }

    /// Records where decisions are shipped and what may be recorded of a caller.
    ///
    /// Structured, so it comes from the file rather than the layered pipeline —
    /// a server with its trust material has no single-variable form.
    pub fn with_log_destination(
        mut self,
        destination: Option<crate::decisions::LogDestination>,
        include: crate::decisions::IncludeSection,
    ) -> Result<Self> {
        // The same shape check a mirror source gets, for the same reason: a
        // URL that is not a URL is a configuration mistake, and a deployment
        // should hear about it before it starts deciding.
        if let Some(destination) = &destination {
            crate::mirrors::check_source(&crate::mirrors::MirrorSource {
                url: destination.url.clone(),
                tls: destination.tls.clone(),
                zones: Vec::new(),
                ledgers: Vec::new(),
            })
            .context("reading the decision log's server")?;
        }
        self.log_destination = destination;
        self.log_include = include;

        Ok(self)
    }

    /// Records the event store endpoint and validates its transport at startup.
    pub fn with_events_destination(
        mut self,
        destination: Option<crate::decisions::EventDestination>,
    ) -> Result<Self> {
        if let Some(destination) = &destination {
            crate::mirrors::check_source(&crate::mirrors::MirrorSource {
                url: destination.url.clone(),
                tls: destination.tls.clone(),
                zones: Vec::new(),
                ledgers: Vec::new(),
            })
            .context("reading the event store's server")?;

            let scheme = destination
                .url
                .split_once("://")
                .map(|(scheme, _)| scheme)
                .unwrap_or_default();
            let matches = match destination.transport.as_str() {
                "http" => matches!(scheme, "http" | "https"),
                "grpc" => matches!(scheme, "grpc" | "grpcs"),
                other => anyhow::bail!(
                    "reading the event store's server: `{other}` is not a transport; use `http` \
                     or `grpc`"
                ),
            };
            if !matches {
                anyhow::bail!(
                    "reading the event store's server: transport `{}` disagrees with URL scheme \
                     `{scheme}`",
                    destination.transport
                );
            }
        }
        self.events_destination = destination;

        Ok(self)
    }

    /// Whether this plane receives and keeps decision records.
    pub fn decision_store_enabled(&self) -> bool {
        self.decision_store_enabled
    }

    /// Where it keeps them, under the working directory.
    pub fn decision_store_directory(&self) -> &str {
        &self.decision_store_directory
    }

    /// How long it keeps them.
    pub fn decision_store_retention(&self) -> Duration {
        self.decision_store_retention
    }

    /// The published key sets of the producers this plane accepts records from.
    pub fn decision_producer_keys(&self) -> &[String] {
        &self.decision_producer_keys
    }

    /// Records where a control plane's producers publish their keys.
    ///
    /// Structured, so it comes from the file: a list of paths has no sensible
    /// single-variable form.
    pub fn with_decision_producer_keys(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.decision_producer_keys = keys.into_iter().collect();

        self
    }

    /// The published key sets of the producers this plane accepts *event* records from.
    ///
    /// Each source binds key material to a producer and an allowed zone/ledger scope. Event
    /// evidence never falls back to the unbound decision-key list.
    pub fn event_producer_keys(&self) -> &[crate::decisions::EventProducerSource] {
        &self.event_producer_keys
    }

    /// Whether the event producers were named in their own right.
    pub fn event_producer_keys_declared(&self) -> bool {
        !self.event_producer_keys.is_empty()
    }

    /// Records where a control plane's *event* producers publish their keys.
    pub fn with_event_producer_keys(
        mut self,
        keys: impl IntoIterator<Item = crate::decisions::EventProducerSource>,
    ) -> Self {
        self.event_producer_keys = keys.into_iter().collect();

        self
    }

    /// How many compiled partitions a data plane keeps in memory.
    pub fn authz_cache_partitions(&self) -> usize {
        self.authz_cache_partitions
    }

    /// How many bytes of compiled partitions it may hold before pruning.
    pub fn authz_cache_bytes(&self) -> u64 {
        self.authz_cache_bytes
    }

    /// The most evaluations one boxcarred request may carry.
    pub fn authz_max_evaluations(&self) -> usize {
        self.authz_max_evaluations
    }

    /// How many pieces of blocking work may run at once — see [`SETTING_MAX_BLOCKING`].
    pub fn max_blocking(&self) -> usize {
        self.max_blocking
    }

    /// How often the synchronization loop runs.
    pub fn mirrors_interval(&self) -> Duration {
        self.mirrors_interval
    }

    /// How long one ledger may take before this round abandons it.
    pub fn mirrors_timeout(&self) -> Duration {
        self.mirrors_timeout
    }

    /// How many ledgers are mirrored at once.
    pub fn mirrors_parallelism(&self) -> usize {
        self.mirrors_parallelism
    }

    /// The fraction of the interval spread randomly across ticks.
    pub fn mirrors_jitter(&self) -> f64 {
        self.mirrors_jitter
    }

    /// How old a mirror's last verified synchronization may grow before the plane alarms.
    /// `None` means no bound.
    pub fn mirrors_stale_after(&self) -> Option<Duration> {
        self.mirrors_stale_after
    }

    /// How old it may grow before the plane refuses to answer from it. `None` means no bound.
    pub fn mirrors_expire_after(&self) -> Option<Duration> {
        self.mirrors_expire_after
    }

    /// The servers this plane follows, and the zone and ledger patterns of
    /// each — as the configuration file declared them.
    pub fn mirror_sources(&self) -> &[crate::mirrors::MirrorSource] {
        &self.mirror_sources
    }

    /// Whether spans leave the process over OTLP.
    pub fn otel_enabled(&self) -> bool {
        self.otel_enabled
    }

    /// Where they go: the OTLP/gRPC collector endpoint.
    pub fn otel_endpoint(&self) -> &str {
        &self.otel_endpoint
    }

    /// What fraction of traces is kept, `0.0`..=`1.0`.
    pub fn otel_sample_rate(&self) -> f64 {
        self.otel_sample_rate
    }

    /// Returns the most objects one NOTP batch may carry.
    pub fn notp_max_batch_objects(&self) -> u64 {
        self.notp_max_batch_objects
    }

    /// Returns the most objects one push delta may declare.
    pub fn notp_max_push_objects(&self) -> u64 {
        self.notp_max_push_objects
    }

    /// Returns the most bytes one push delta may declare.
    pub fn notp_max_push_bytes(&self) -> u64 {
        self.notp_max_push_bytes
    }

    /// Returns the storage quota of one ledger's objects, in bytes.
    pub fn notp_ledger_quota_bytes(&self) -> u64 {
        self.notp_ledger_quota_bytes
    }

    /// Reports whether this deployment publishes signing keys.
    pub fn keys_enabled(&self) -> bool {
        self.keys_enabled
    }

    /// Returns where everything this server **keeps** lives: `<volume>/data`.
    ///
    /// One rule decides what goes here rather than beside it: `data/` is what a restore has to
    /// bring back, and `operations/` is how the server runs itself — its rings, its trail, its
    /// secrets, its state. A volume laid out by *duty* stays readable when a deployment adds a
    /// second plane to it, which is exactly when a flat root stops being readable.
    ///
    /// ```text
    /// <volume>/data/zones/<zone>/<ledger>/    the ledgers          (control plane)
    /// <volume>/data/mirrors/<zone>/<ledger>/  verified copies      (data plane)
    /// <volume>/data/decisions/store/          the decision log     (control plane)
    /// <volume>/data/decisions/spool/          records not yet shipped (data plane)
    /// ```
    pub fn data_directory(&self) -> PathBuf {
        self.working_dir().join("data")
    }

    /// Returns where the catalog of zones — and inside them, the ledgers' git-like stores — lives:
    /// `<volume>/data/zones`. One expression, used by everything that touches that layout, so the
    /// catalog and the object store can never disagree about where a ledger is.
    pub fn zones_directory(&self) -> PathBuf {
        self.data_directory().join("zones")
    }

    /// Returns where a data plane keeps its verified copies of ledgers:
    /// `<volume>/data/mirrors`.
    ///
    /// Beside `zones` rather than at the root, and the reason is the same one: a mirror **is** a
    /// ledger — the same objects, the same refs, verified before the checkpoint moved — so an
    /// operator who has seen one has seen both. The all-in-one holds the two side by side and the
    /// symmetry is the point.
    pub fn mirrors_directory(&self) -> PathBuf {
        self.data_directory().join("mirrors")
    }

    /// Returns where the **operations** ring lives — the ring that seals the audit trail:
    /// `<keys>/operations`. Its own directory beside the plane rings, so the three rings this
    /// server rotates are three sibling folders and nothing lives ambiguously at the root.
    pub fn operations_keys_directory(&self) -> PathBuf {
        self.keys_directory().join("operations")
    }

    /// Reports whether the control plane composes its signing ring — the ring that signs what the
    /// control plane serves (git-like head statements today). Absent an explicit choice it follows
    /// `keys.enabled`, because a deployment that signs anything signs what it serves too.
    pub fn control_signing_keys_enabled(&self) -> bool {
        self.control_keys_enabled.unwrap_or(self.keys_enabled)
    }

    /// Returns where the control plane's signing ring lives: `<volume>/keys/control` unless said
    /// otherwise. Deliberately not the operations ring that seals the audit trail: different duty,
    /// different rotation, different blast radius when compromised.
    pub fn control_signing_keys_directory(&self) -> PathBuf {
        match &self.control_keys_directory {
            Some(directory) => self.resolve(directory),
            None => self.keys_directory().join("control"),
        }
    }

    /// Reports whether the data plane composes its signing ring — the ring that will sign the
    /// decision responses it returns. Absent an explicit choice it follows `keys.enabled`, like
    /// the control plane's: the signing rings are part of the model on every plane.
    pub fn data_signing_keys_enabled(&self) -> bool {
        self.data_keys_enabled.unwrap_or(self.keys_enabled)
    }

    /// Returns where the data plane's signing ring lives: `<volume>/keys/data` unless said otherwise.
    pub fn data_signing_keys_directory(&self) -> PathBuf {
        match &self.data_keys_directory {
            Some(directory) => self.resolve(directory),
            None => self.keys_directory().join("data"),
        }
    }

    /// Returns the directory the key ring lives in, resolved against the volume.
    pub fn keys_directory(&self) -> PathBuf {
        self.resolve(
            self.keys_directory
                .as_deref()
                .unwrap_or(DEFAULT_KEYS_SUBDIRECTORY),
        )
    }

    /// Returns the realms this deployment hosts, in a stable order.
    ///
    /// Empty is the ordinary single-issuer deployment: a server that hosts no separate realm and
    /// serves everything under its own root. Adding realms is additive.
    pub fn realms(&self) -> &[RealmConfig] {
        &self.realms
    }

    /// Returns where `realm`'s operations key ring lives: `<volume>/realms/<name>/operations/keys`.
    ///
    /// The ring that signs *this realm's* trail — an internal duty, like the server's own, so it sits
    /// under `operations/` beside the trail it seals and never appears on the public key set. The keys
    /// a realm signs *tokens* with are a different ring at [`Config::realm_token_keys_directory`].
    ///
    /// The convention is here, in one place, so the service that rotates a realm's keys and the sink
    /// that seals with them cannot disagree about where they are.
    pub fn realm_keys_directory(&self, realm: &str) -> PathBuf {
        self.resolve(format!("realms/{realm}/operations/keys"))
    }

    /// Returns where `realm`'s token-signing key ring lives: `<volume>/realms/<name>/keys`.
    ///
    /// A realm's reason to exist: the keys it signs the tokens it issues with, published at its
    /// `jwks_uri` for relying parties. Kept at the realm's top level — for a realm, *these* are "its
    /// keys" — and separate from the operations ring, because a token key and an audit-sealing key
    /// need opposite lifetimes. Reserved: nothing writes here until token issuance exists.
    pub fn realm_token_keys_directory(&self, realm: &str) -> PathBuf {
        self.resolve(format!("realms/{realm}/keys"))
    }

    /// Returns where `realm`'s audit trail lives: `<volume>/realms/<name>/operations/audit`.
    pub fn realm_audit_directory(&self, realm: &str) -> PathBuf {
        self.resolve(format!("realms/{realm}/operations/audit"))
    }

    /// Returns where `realm`'s secret material is resolved from:
    /// `<volume>/realms/<name>/operations/secrets`.
    pub fn realm_secrets_directory(&self, realm: &str) -> PathBuf {
        self.resolve(format!("realms/{realm}/operations/secrets"))
    }

    /// Returns how long a new key is published before it starts signing.
    pub fn keys_publish_ahead(&self) -> Duration {
        self.keys_publish_ahead
    }

    /// Returns how long a key signs before it is replaced.
    pub fn keys_rotate_every(&self) -> Duration {
        self.keys_rotate_every
    }

    /// Returns how long a retired key stays published.
    pub fn keys_retain(&self) -> Duration {
        self.keys_retain
    }

    /// Returns how often the key lifecycle is advanced — one cadence for every ring in the process.
    pub fn keys_maintenance_interval(&self) -> Duration {
        self.keys_maintenance_interval
    }

    /// Returns the effective value of a declared setting, when any layer supplied one.
    ///
    /// A key this build never declared reads back as `None` even when the environment defines it.
    pub fn setting(&self, key: &str) -> Option<&str> {
        self.declared_values.get(key).map(String::as_str)
    }

    /// Returns the extra setting keys this build declared.
    pub fn declared_settings(&self) -> impl Iterator<Item = &str> {
        self.declared.iter().map(String::as_str)
    }

    /// The listen addresses the assembled config actually declares, labelled for diagnostics.
    fn declared_addresses(&self) -> Result<Vec<(String, &str)>> {
        let mut addresses = [
            ("public.http", self.public_http_addr()),
            ("public.grpc", self.public_grpc_addr()),
            ("telemetry", self.telemetry_addr()),
            ("admin", self.admin_addr()),
        ]
        .into_iter()
        .filter_map(|(label, addr)| addr.map(|addr| (label.to_owned(), addr)))
        .collect::<Vec<_>>();

        addresses.extend(self.declared_extra_addresses()?);

        Ok(addresses)
    }

    fn declared_extra_addresses(&self) -> Result<Vec<(String, &str)>> {
        let mut addresses = Vec::new();

        for (key, value) in &self.declared_values {
            if !is_declared_listen_address(key) {
                continue;
            }

            let enabled_key = format!("{}_ENABLED", key.trim_end_matches("_ADDR"));
            if let Some(enabled) = self.declared_values.get(&enabled_key)
                && !parse_bool(enabled).with_context(|| format!("reading {enabled_key}"))?
            {
                continue;
            }

            addresses.push((setting_label(key), value.as_str()));
        }

        Ok(addresses)
    }

    fn apply_build_settings(&mut self, build_settings: BuildSettings) {
        self.version = build_settings.version.to_owned();
        self.commit = build_settings.commit.to_owned();
        self.copyright_year = build_settings.copyright_year.to_owned();
        self.copyright_holder = build_settings.copyright_holder.to_owned();
    }

    fn apply_pairs<I>(&mut self, inputs: I) -> Result<()>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        // An empty value means the setting was not supplied. Every tool that composes an environment
        // — a shell, a Taskfile, a container runtime, a Kubernetes manifest — expresses "leave this
        // alone" by setting the variable to nothing, and reading that as a configured empty path is
        // how a deployment ends up refusing to start over a certificate nobody asked for.
        //
        // Whitespace is *not* empty: `"   "` as an address is a typo, and silently treating it as
        // absent would hide the typo instead of reporting it.
        let settings: BTreeMap<String, String> = inputs
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .collect();

        if let Some(value) = settings.get(SETTING_VERSION) {
            self.version.clone_from(value);
        }

        if let Some(value) = settings.get(SETTING_COPYRIGHT_YEAR) {
            self.copyright_year.clone_from(value);
        }

        if let Some(value) = settings.get(SETTING_COPYRIGHT_HOLDER) {
            self.copyright_holder.clone_from(value);
        }

        if let Some(value) = settings.get(SETTING_WORKING_DIR) {
            self.working_dir = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_AUTOGENERATE) {
            self.autogenerate =
                parse_bool(value).with_context(|| format!("reading {SETTING_AUTOGENERATE}"))?;
        }

        if let Some(value) = settings.get(SETTING_DEVELOPMENT_MODE) {
            self.development_mode =
                parse_bool(value).with_context(|| format!("reading {SETTING_DEVELOPMENT_MODE}"))?;
        }

        if let Some(value) = settings.get(SETTING_ISSUER) {
            self.issuer = Some(value.trim_end_matches('/').to_owned());
        }

        if let Some(value) = settings.get(SETTING_PUBLIC_PATH_PREFIX) {
            self.public_path_prefix = value.trim_end_matches('/').to_owned();
        }

        if let Some(value) = settings.get(SETTING_PUBLIC_HTTP_ENABLED) {
            self.public_http_enabled = parse_bool(value)
                .with_context(|| format!("reading {SETTING_PUBLIC_HTTP_ENABLED}"))?;
        }

        if let Some(value) = settings.get(SETTING_PUBLIC_HTTP_ADDR) {
            self.public_http_addr = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_PUBLIC_GRPC_ENABLED) {
            self.public_grpc_enabled = parse_bool(value)
                .with_context(|| format!("reading {SETTING_PUBLIC_GRPC_ENABLED}"))?;
        }

        if let Some(value) = settings.get(SETTING_PUBLIC_GRPC_ADDR) {
            self.public_grpc_addr = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_TELEMETRY_ADDR) {
            self.telemetry_addr = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_ADMIN_ADDR) {
            self.admin_addr = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_PUBLIC_DISCLOSE_BUILD) {
            self.disclose_build = parse_bool(value)
                .with_context(|| format!("reading {SETTING_PUBLIC_DISCLOSE_BUILD}"))?;
        }

        if let Some(value) = settings.get(SETTING_PUBLIC_ERROR_DETAIL) {
            self.error_detail = Some(value.parse().map_err(|error: String| anyhow!(error))?);
        }

        if let Some(value) = settings.get(SETTING_ADMIN_ALLOW) {
            self.admin_allow =
                parse_allowed(value).with_context(|| format!("reading {SETTING_ADMIN_ALLOW}"))?;
        }

        if let Some(value) = settings.get(SETTING_LOG_LEVEL) {
            self.log_level = value
                .parse()
                .with_context(|| format!("reading {SETTING_LOG_LEVEL}"))?;
        }

        if let Some(value) = settings.get(SETTING_LOG_FORMAT) {
            self.log_format = value
                .parse()
                .with_context(|| format!("reading {SETTING_LOG_FORMAT}"))?;
        }

        self.public_tls = tls_of(
            &settings,
            SETTING_PUBLIC_TLS_CERT,
            SETTING_PUBLIC_TLS_KEY,
            TlsKeys {
                client_ca: Some(SETTING_PUBLIC_TLS_CLIENT_CA),
                crl: Some(SETTING_PUBLIC_TLS_CRL),
                allow: Some(SETTING_PUBLIC_TLS_ALLOW),
                min_version: SETTING_PUBLIC_TLS_MIN_VERSION,
            },
            self.public_tls.take(),
        )?;

        self.admin_tls = tls_of(
            &settings,
            SETTING_ADMIN_TLS_CERT,
            SETTING_ADMIN_TLS_KEY,
            TlsKeys {
                client_ca: Some(SETTING_ADMIN_TLS_CLIENT_CA),
                crl: Some(SETTING_ADMIN_TLS_CRL),
                // The administrative surface's peers are `admin.allow`, kept beside its address
                // rather than inside its TLS block.
                allow: None,
                min_version: SETTING_ADMIN_TLS_MIN_VERSION,
            },
            self.admin_tls.take(),
        )?;

        self.telemetry_tls = tls_of(
            &settings,
            SETTING_TELEMETRY_TLS_CERT,
            SETTING_TELEMETRY_TLS_KEY,
            TlsKeys {
                // Telemetry never demands a certificate, so there is neither an authority to name
                // nor a list to check against.
                client_ca: None,
                crl: None,
                allow: None,
                min_version: SETTING_TELEMETRY_TLS_MIN_VERSION,
            },
            self.telemetry_tls.take(),
        )?;

        if let Some(value) = settings.get(SETTING_TLS_RELOAD) {
            self.tls_reload =
                parse_bool(value).with_context(|| format!("reading {SETTING_TLS_RELOAD}"))?;
        }

        if let Some(value) = settings.get(SETTING_TLS_RELOAD_INTERVAL) {
            self.tls_reload_interval = parse_duration(value)
                .with_context(|| format!("reading {SETTING_TLS_RELOAD_INTERVAL}"))?;
        }

        if let Some(value) = settings.get(SETTING_LIMITS_CONNECTIONS) {
            self.limits = self.limits.clone().with_connections(
                parse_count(value)
                    .with_context(|| format!("reading {SETTING_LIMITS_CONNECTIONS}"))?,
            );
        }

        if let Some(value) = settings.get(SETTING_LIMITS_CONNECTIONS_PER_PEER) {
            // `parse_count` refuses zero because a pool of zero accepts nothing; here zero is the
            // documented way to switch the bound off, so it is read as a plain number.
            let count: u32 = value.trim().parse().map_err(|_| {
                anyhow!("reading {SETTING_LIMITS_CONNECTIONS_PER_PEER}: `{value}` is not a count")
            })?;

            self.limits = self.limits.clone().with_connections_per_peer(count);
        }

        if let Some(value) = settings.get(SETTING_LIMITS_PEER_EXEMPT) {
            let exempt = value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(|entry| {
                    entry
                        .parse::<PeerBlock>()
                        .map_err(|error| anyhow!("reading {SETTING_LIMITS_PEER_EXEMPT}: {error}"))
                })
                .collect::<Result<Vec<_>>>()?;

            self.limits = self.limits.clone().with_peer_exempt(exempt);
        }

        if let Some(value) = settings.get(SETTING_LIMITS_CONNECTION_LIFETIME) {
            let lifetime = parse_duration_allow_zero(value)
                .with_context(|| format!("reading {SETTING_LIMITS_CONNECTION_LIFETIME}"))?;

            self.limits = self
                .limits
                .clone()
                .with_connection_lifetime((!lifetime.is_zero()).then_some(lifetime));
        }

        if let Some(value) = settings.get(SETTING_LIMITS_WRITE_STALL_TIMEOUT) {
            self.limits =
                self.limits
                    .clone()
                    .with_write_stall_timeout(parse_duration(value).with_context(|| {
                        format!("reading {SETTING_LIMITS_WRITE_STALL_TIMEOUT}")
                    })?);
        }

        if let Some(value) = settings.get(SETTING_LIMITS_CONCURRENT_REQUESTS) {
            self.limits =
                self.limits
                    .clone()
                    .with_concurrent_requests(parse_count(value).with_context(|| {
                        format!("reading {SETTING_LIMITS_CONCURRENT_REQUESTS}")
                    })?);
        }

        if let Some(value) = settings.get(SETTING_LIMITS_REQUEST_TIMEOUT) {
            self.limits = self.limits.clone().with_request_timeout(
                parse_duration(value)
                    .with_context(|| format!("reading {SETTING_LIMITS_REQUEST_TIMEOUT}"))?,
            );
        }

        if let Some(value) = settings.get(SETTING_LIMITS_HANDSHAKE_TIMEOUT) {
            self.limits = self.limits.clone().with_handshake_timeout(
                parse_duration(value)
                    .with_context(|| format!("reading {SETTING_LIMITS_HANDSHAKE_TIMEOUT}"))?,
            );
        }

        if let Some(value) = settings.get(SETTING_LIMITS_HEADER_TIMEOUT) {
            self.limits = self.limits.clone().with_header_timeout(
                parse_duration(value)
                    .with_context(|| format!("reading {SETTING_LIMITS_HEADER_TIMEOUT}"))?,
            );
        }

        if let Some(value) = settings.get(SETTING_LIMITS_HEADER_BYTES) {
            self.limits = self.limits.clone().with_header_bytes(
                parse_bytes(value)
                    .with_context(|| format!("reading {SETTING_LIMITS_HEADER_BYTES}"))?
                    as usize,
            );
        }

        if let Some(value) = settings.get(SETTING_LIMITS_BODY_BYTES) {
            self.limits = self.limits.clone().with_body_bytes(
                parse_bytes(value)
                    .with_context(|| format!("reading {SETTING_LIMITS_BODY_BYTES}"))?
                    as usize,
            );
        }

        if let Some(value) = settings.get(SETTING_SHUTDOWN_TIMEOUT) {
            self.shutdown_timeout = parse_duration(value)
                .with_context(|| format!("reading {SETTING_SHUTDOWN_TIMEOUT}"))?;
        }

        if let Some(value) = settings.get(SETTING_SECRETS_PROVIDER) {
            self.secrets_provider = value
                .parse()
                .with_context(|| format!("reading {SETTING_SECRETS_PROVIDER}"))?;
        }

        if let Some(value) = settings.get(SETTING_SECRETS_DIRECTORY) {
            self.secrets_directory = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_SECRETS_ENV_PREFIX) {
            self.secrets_env_prefix.clone_from(value);
        }

        if let Some(value) = settings.get(SETTING_AUDIT_PSEUDONYM_ENABLED) {
            self.audit_pseudonym_enabled = parse_bool(value)
                .with_context(|| format!("reading {SETTING_AUDIT_PSEUDONYM_ENABLED}"))?;
        }

        if let Some(value) = settings.get(SETTING_AUDIT_PSEUDONYM_KEY_REF) {
            self.audit_pseudonym_key_ref = Some(SecretRef::new(value.clone()));
        }

        if let Some(value) = settings.get(SETTING_AUDIT_PSEUDONYM_KEY_VERSION) {
            self.audit_pseudonym_key_version.clone_from(value);
        }

        if let Some(value) = settings.get(SETTING_AUDIT_SINK) {
            self.audit_destination = value
                .parse()
                .with_context(|| format!("reading {SETTING_AUDIT_SINK}"))?;
        }

        if let Some(value) = settings.get(SETTING_AUDIT_DIRECTORY) {
            self.audit_directory = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_AUDIT_REFUSALS) {
            self.audit_refusals =
                parse_bool(value).with_context(|| format!("reading {SETTING_AUDIT_REFUSALS}"))?;
        }

        if let Some(value) = settings.get(SETTING_GC_ENABLED) {
            self.gc_enabled =
                parse_bool(value).with_context(|| format!("reading {SETTING_GC_ENABLED}"))?;
        }
        if let Some(value) = settings.get(SETTING_GC_INTERVAL) {
            self.gc_interval =
                parse_duration(value).with_context(|| format!("reading {SETTING_GC_INTERVAL}"))?;
            if self.gc_interval.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_GC_INTERVAL}: a sweep every no-time is a sweep that never \
                     stops sweeping"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_GC_GRACE) {
            self.gc_grace =
                parse_duration(value).with_context(|| format!("reading {SETTING_GC_GRACE}"))?;
            if self.gc_grace < MINIMUM_GC_GRACE {
                anyhow::bail!(
                    "reading {SETTING_GC_GRACE}: `{value}` is shorter than {}s, which is the \
                     shortest window that cannot delete the uploads of a push in flight",
                    MINIMUM_GC_GRACE.as_secs()
                );
            }
        }
        if let Some(value) = settings.get(SETTING_LOG_ENABLED) {
            self.log_enabled =
                parse_bool(value).with_context(|| format!("reading {SETTING_LOG_ENABLED}"))?;
        }
        if let Some(value) = settings.get(SETTING_LOG_PDP_ID) {
            self.log_pdp_id = value.trim().to_owned();
        }
        if let Some(value) = settings.get(SETTING_LOG_SPOOL_DIRECTORY) {
            self.log_spool_directory = value.trim().to_owned();
            if self.log_spool_directory.is_empty() {
                anyhow::bail!(
                    "reading {SETTING_LOG_SPOOL_DIRECTORY}: the spool needs a directory of its own"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENT_STORE_ENABLED) {
            self.event_store_enabled = parse_bool(value)
                .with_context(|| format!("reading {SETTING_EVENT_STORE_ENABLED}"))?;
        }
        if let Some(value) = settings.get(SETTING_EVENT_STORE_DIRECTORY) {
            self.event_store_directory = value.trim().to_owned();
            if self.event_store_directory.is_empty() {
                anyhow::bail!(
                    "reading {SETTING_EVENT_STORE_DIRECTORY}: the event store needs a directory of \
                     its own"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENT_STORE_RETENTION) {
            self.event_store_retention = parse_duration(value)
                .with_context(|| format!("reading {SETTING_EVENT_STORE_RETENTION}"))?;
            if self.event_store_retention.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_EVENT_STORE_RETENTION}: a store that keeps nothing is not a \
                     store, and a plane that received events and dropped them immediately would \
                     acknowledge history it did not keep"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENTS_ENABLED) {
            self.events_enabled =
                parse_bool(value).with_context(|| format!("reading {SETTING_EVENTS_ENABLED}"))?;
        }
        if let Some(value) = settings.get(SETTING_EVENTS_PRODUCER_ID) {
            self.events_producer_id = value.trim().to_owned();
        }
        if let Some(value) = settings.get(SETTING_EVENTS_DIRECTORY) {
            self.events_directory = value.trim().to_owned();
            if self.events_directory.is_empty() {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_DIRECTORY}: the event journals need a directory of \
                     their own"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENTS_MAX_BYTES) {
            self.events_max_bytes = parse_bytes(value)
                .with_context(|| format!("reading {SETTING_EVENTS_MAX_BYTES}"))?;
            if self.events_max_bytes == 0 {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_MAX_BYTES}: a journal of no bytes refuses the first \
                     event, and a refused event is a decision not made"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENTS_SEGMENT_BYTES) {
            self.events_segment_bytes = parse_bytes(value)
                .with_context(|| format!("reading {SETTING_EVENTS_SEGMENT_BYTES}"))?;
            if self.events_segment_bytes == 0 {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_SEGMENT_BYTES}: a segment of no bytes holds no records"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENTS_MAX_RECORD_BYTES) {
            self.events_max_record_bytes = parse_bytes(value)
                .with_context(|| format!("reading {SETTING_EVENTS_MAX_RECORD_BYTES}"))?;
            if self.events_max_record_bytes == 0 {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_MAX_RECORD_BYTES}: no record fits in no bytes"
                );
            }
            if self.events_max_record_bytes > self.events_segment_bytes {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_MAX_RECORD_BYTES}: a record larger than a segment \
                     ({}) can never be written, so every submission would be refused",
                    self.events_segment_bytes
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENTS_RETENTION_MINIMUM) {
            self.events_retention_minimum = parse_duration(value)
                .with_context(|| format!("reading {SETTING_EVENTS_RETENTION_MINIMUM}"))?;
            if self.events_retention_minimum.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_RETENTION_MINIMUM}: a history kept for no time is a \
                     history every temporal policy reads as empty"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENTS_ALLOWED_LATENESS) {
            self.events_allowed_lateness = parse_duration(value)
                .with_context(|| format!("reading {SETTING_EVENTS_ALLOWED_LATENESS}"))?;
        }
        if let Some(value) = settings.get(SETTING_EVENTS_CLOCK_SKEW) {
            self.events_clock_skew = parse_duration(value)
                .with_context(|| format!("reading {SETTING_EVENTS_CLOCK_SKEW}"))?;
        }
        // Every `experimental.<name>.enabled`, by pattern: the runtimes are named by the languages
        // this build carries, not by a list kept here, so the reader must not need one either.
        for (key, value) in &settings {
            let Some(name) = experimental_setting_name(key) else {
                continue;
            };
            let on = parse_bool(value).with_context(|| format!("reading {key}"))?;
            self.experimental.insert(name, on);
        }
        if let Some(value) = settings.get(SETTING_EVENTS_GROUP_COMMIT_DELAY) {
            self.events_group_commit_delay = parse_duration(value)
                .with_context(|| format!("reading {SETTING_EVENTS_GROUP_COMMIT_DELAY}"))?;
        }
        if let Some(value) = settings.get(SETTING_EVENTS_PULL_MODE) {
            self.events_pull_mode = Consistency::parse(value).ok_or_else(|| {
                anyhow!(
                    "reading {SETTING_EVENTS_PULL_MODE}: `{value}` is not a consistency mode; \
                     they are `local`, `shared-eventual` and `shared-bounded`"
                )
            })?;
        }
        if let Some(value) = settings.get(SETTING_EVENTS_PULL_INTERVAL) {
            self.events_pull_interval = parse_duration(value)
                .with_context(|| format!("reading {SETTING_EVENTS_PULL_INTERVAL}"))?;
            if self.events_pull_interval.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_PULL_INTERVAL}: a worker that never waits is a worker \
                     that spends a control plane's capacity on asking"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_EVENTS_PULL_MAX_STALENESS) {
            self.events_pull_max_staleness = parse_duration(value)
                .with_context(|| format!("reading {SETTING_EVENTS_PULL_MAX_STALENESS}"))?;
            if self.events_pull_max_staleness.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_EVENTS_PULL_MAX_STALENESS}: a staleness bound of zero fails \
                     every decision closed, because replication is never instantaneous"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_LOG_SPOOL_BYTES) {
            self.log_spool_bytes =
                parse_bytes(value).with_context(|| format!("reading {SETTING_LOG_SPOOL_BYTES}"))?;
            if self.log_spool_bytes == 0 {
                anyhow::bail!(
                    "reading {SETTING_LOG_SPOOL_BYTES}: a spool of no bytes ends its stream on the \
                     first decision"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_LOG_SPOOL_AGE) {
            self.log_spool_age = parse_duration(value)
                .with_context(|| format!("reading {SETTING_LOG_SPOOL_AGE}"))?;
            if self.log_spool_age.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_LOG_SPOOL_AGE}: a record that expires immediately is a record \
                     that is never shipped"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_LOG_BATCH_BYTES) {
            self.log_batch_bytes =
                parse_bytes(value).with_context(|| format!("reading {SETTING_LOG_BATCH_BYTES}"))?;
            if self.log_batch_bytes == 0 {
                anyhow::bail!("reading {SETTING_LOG_BATCH_BYTES}: an empty batch is not shipped");
            }
        }
        if let Some(value) = settings.get(SETTING_LOG_BATCH_INTERVAL) {
            self.log_batch_interval = parse_duration(value)
                .with_context(|| format!("reading {SETTING_LOG_BATCH_INTERVAL}"))?;
            if self.log_batch_interval.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_LOG_BATCH_INTERVAL}: a batch every no-time is a batch per \
                     decision, which is what batching exists to avoid"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_LOG_ON_FULL) {
            self.log_on_full_open = match value.trim() {
                "open" => true,
                "closed" => false,
                other => anyhow::bail!(
                    "reading {SETTING_LOG_ON_FULL}: `{other}` is neither `open` (keep answering, \
                     end the stream with a signed discontinuity) nor `closed` (refuse to decide \
                     rather than decide unrecorded)"
                ),
            };
        }
        if let Some(value) = settings.get(SETTING_LOG_SAMPLE_PERMITS) {
            self.log_sample_permits = value
                .parse()
                .with_context(|| format!("reading {SETTING_LOG_SAMPLE_PERMITS}"))?;
            if !(0.0..=1.0).contains(&self.log_sample_permits) {
                anyhow::bail!(
                    "reading {SETTING_LOG_SAMPLE_PERMITS}: `{value}` is not a rate between 0.0 and \
                     1.0"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_LOG_COMMITMENT_KEY_REF) {
            self.log_commitment_key_ref = Some(SecretRef::new(value.clone()));
        }
        if let Some(value) = settings.get(SETTING_LOG_COMMITMENT_KEY_VERSION) {
            self.log_commitment_key_version = value.trim().to_owned();
            if self.log_commitment_key_version.is_empty() {
                anyhow::bail!(
                    "reading {SETTING_LOG_COMMITMENT_KEY_VERSION}: a key with no version cannot be \
                     rotated, because nothing can say which one produced a commitment"
                );
            }
        }
        // A commitment keyed by something public is a bare digest, and a bare digest of a
        // low-entropy caller attribute is a dictionary away from the attribute. Refused at
        // startup rather than discovered by whoever reads the log.
        if self.log_enabled && self.log_commitment_key_ref.is_none() {
            anyhow::bail!(
                "the decision log is on but no {SETTING_LOG_COMMITMENT_KEY_REF} is set: input \
                 commitments would be keyed by nothing secret, and a reader could recover \
                 low-entropy caller attributes from them by trying values"
            );
        }

        // The decision log records who asked. Every record leaves this plane and is kept for as
        // long as the retention says, so an identifier in clear is a personal identifier in an
        // audit store — which is a decision a deployment makes deliberately or not at all.
        if self.log_enabled && !self.audit_pseudonym_enabled {
            anyhow::bail!(
                "the decision log is on and `operations.audit.pseudonym` is off: subjects would \
                 reach the control plane as raw identifiers. Turn pseudonymisation on, or turn \
                 the decision log off"
            );
        }

        // A stream is `(pdp.id, instance)`. Two replicas sharing a `pdp.id` write two records at
        // one `(stream, seq)`, and that closes a stream permanently at the far end — so it is
        // refused here, at startup, rather than discovered there.
        if self.log_enabled && self.log_pdp_id.is_empty() {
            anyhow::bail!(
                "the decision log is on but no {SETTING_LOG_PDP_ID} is set: a plane with no name \
                 cannot be told from another replica of itself"
            );
        }

        if let Some(value) = settings.get(SETTING_DECISION_STORE_ENABLED) {
            self.decision_store_enabled = parse_bool(value)
                .with_context(|| format!("reading {SETTING_DECISION_STORE_ENABLED}"))?;
        }
        if let Some(value) = settings.get(SETTING_DECISION_STORE_DIRECTORY) {
            self.decision_store_directory = value.trim().to_owned();
            if self.decision_store_directory.is_empty() {
                anyhow::bail!(
                    "reading {SETTING_DECISION_STORE_DIRECTORY}: the store needs a directory of \
                     its own"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_DECISION_STORE_RETENTION) {
            self.decision_store_retention = parse_duration(value)
                .with_context(|| format!("reading {SETTING_DECISION_STORE_RETENTION}"))?;
            if self.decision_store_retention.is_zero() {
                anyhow::bail!(
                    "reading {SETTING_DECISION_STORE_RETENTION}: a record that is kept for no time \
                     is a record that was never worth receiving"
                );
            }
        }

        if let Some(value) = settings.get(SETTING_AUTHZ_CACHE_PARTITIONS) {
            self.authz_cache_partitions = value
                .parse()
                .with_context(|| format!("reading {SETTING_AUTHZ_CACHE_PARTITIONS}"))?;
            if self.authz_cache_partitions == 0 {
                anyhow::bail!(
                    "reading {SETTING_AUTHZ_CACHE_PARTITIONS}: a cache that holds nothing would \
                     compile every partition on every request"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_AUTHZ_CACHE_BYTES) {
            self.authz_cache_bytes = parse_bytes(value)
                .with_context(|| format!("reading {SETTING_AUTHZ_CACHE_BYTES}"))?;
            if self.authz_cache_bytes == 0 {
                anyhow::bail!(
                    "reading {SETTING_AUTHZ_CACHE_BYTES}: a cache of no bytes holds nothing"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_MAX_BLOCKING) {
            self.max_blocking = value
                .parse()
                .with_context(|| format!("reading {SETTING_MAX_BLOCKING}"))?;
            if self.max_blocking == 0 {
                anyhow::bail!(
                    "reading {SETTING_MAX_BLOCKING}: a bound of zero would refuse every request \
                     that has to touch a disk or evaluate a policy, which is every request"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_AUTHZ_MAX_EVALUATIONS) {
            self.authz_max_evaluations = value
                .parse()
                .with_context(|| format!("reading {SETTING_AUTHZ_MAX_EVALUATIONS}"))?;
            if self.authz_max_evaluations == 0 {
                anyhow::bail!(
                    "reading {SETTING_AUTHZ_MAX_EVALUATIONS}: zero evaluations means no request \
                     can ever be answered"
                );
            }
        }
        if let Some(value) = settings.get(SETTING_MIRRORS_ENABLED) {
            self.mirrors_enabled =
                parse_bool(value).with_context(|| format!("reading {SETTING_MIRRORS_ENABLED}"))?;
        }

        if let Some(value) = settings.get(SETTING_MIRRORS_INTERVAL) {
            self.mirrors_interval = parse_duration(value)
                .with_context(|| format!("reading {SETTING_MIRRORS_INTERVAL}"))?;
        }

        if let Some(value) = settings.get(SETTING_MIRRORS_TIMEOUT) {
            self.mirrors_timeout = parse_duration(value)
                .with_context(|| format!("reading {SETTING_MIRRORS_TIMEOUT}"))?;
        }

        if let Some(value) = settings.get(SETTING_MIRRORS_PARALLELISM) {
            let parallelism: usize = value
                .parse()
                .with_context(|| format!("reading {SETTING_MIRRORS_PARALLELISM}"))?;
            if parallelism == 0 {
                anyhow::bail!(
                    "reading {SETTING_MIRRORS_PARALLELISM}: zero mirrors at once means nothing is ever mirrored"
                );
            }
            self.mirrors_parallelism = parallelism;
        }

        if let Some(value) = settings.get(SETTING_MIRRORS_JITTER) {
            let jitter: f64 = value
                .parse()
                .with_context(|| format!("reading {SETTING_MIRRORS_JITTER}"))?;
            if !(0.0..=0.5).contains(&jitter) {
                anyhow::bail!(
                    "reading {SETTING_MIRRORS_JITTER}: `{value}` is not within 0.0..=0.5 of the interval"
                );
            }
            self.mirrors_jitter = jitter;
        }

        if let Some(value) = settings.get(SETTING_MIRRORS_STALE_AFTER) {
            // Zero means no bound, exactly as `limits.connection_lifetime`
            // reads it: the explicit way to write the default down.
            let bound = parse_duration_allow_zero(value)
                .with_context(|| format!("reading {SETTING_MIRRORS_STALE_AFTER}"))?;
            self.mirrors_stale_after = (!bound.is_zero()).then_some(bound);
        }

        if let Some(value) = settings.get(SETTING_MIRRORS_EXPIRE_AFTER) {
            let bound = parse_duration_allow_zero(value)
                .with_context(|| format!("reading {SETTING_MIRRORS_EXPIRE_AFTER}"))?;
            self.mirrors_expire_after = (!bound.is_zero()).then_some(bound);
        }

        if let (Some(stale), Some(expire)) = (self.mirrors_stale_after, self.mirrors_expire_after)
            && expire < stale
        {
            anyhow::bail!(
                "reading {SETTING_MIRRORS_EXPIRE_AFTER}: a mirror cannot expire before it is \
                 stale — expire_after must be at least stale_after"
            );
        }

        if let Some(value) = settings.get(SETTING_OTEL_ENABLED) {
            self.otel_enabled =
                parse_bool(value).with_context(|| format!("reading {SETTING_OTEL_ENABLED}"))?;
        }

        if let Some(value) = settings.get(SETTING_OTEL_ENDPOINT) {
            self.otel_endpoint = value.clone();
        }

        if let Some(value) = settings.get(SETTING_OTEL_SAMPLE_RATE) {
            let rate: f64 = value
                .parse()
                .with_context(|| format!("reading {SETTING_OTEL_SAMPLE_RATE}"))?;
            if !(0.0..=1.0).contains(&rate) {
                anyhow::bail!(
                    "reading {SETTING_OTEL_SAMPLE_RATE}: `{value}` is not within 0.0..=1.0"
                );
            }
            self.otel_sample_rate = rate;
        }

        if let Some(value) = settings.get(SETTING_NOTP_COMPRESSION) {
            self.notp_compression = match value.as_str() {
                "deflate" => true,
                "none" => false,
                other => anyhow::bail!(
                    "reading {SETTING_NOTP_COMPRESSION}: `{other}` is neither `deflate` nor `none`"
                ),
            };
        }

        if let Some(value) = settings.get(SETTING_NOTP_MAX_BATCH_BYTES) {
            self.notp_max_batch_bytes = parse_bytes(value)
                .with_context(|| format!("reading {SETTING_NOTP_MAX_BATCH_BYTES}"))?;
        }

        if let Some(value) = settings.get(SETTING_NOTP_MAX_BATCH_OBJECTS) {
            self.notp_max_batch_objects = value
                .parse()
                .with_context(|| format!("reading {SETTING_NOTP_MAX_BATCH_OBJECTS}"))?;
        }

        if let Some(value) = settings.get(SETTING_NOTP_MAX_PUSH_OBJECTS) {
            self.notp_max_push_objects = value
                .parse()
                .with_context(|| format!("reading {SETTING_NOTP_MAX_PUSH_OBJECTS}"))?;
        }

        if let Some(value) = settings.get(SETTING_NOTP_MAX_PUSH_BYTES) {
            self.notp_max_push_bytes = parse_bytes(value)
                .with_context(|| format!("reading {SETTING_NOTP_MAX_PUSH_BYTES}"))?;
        }

        if let Some(value) = settings.get(SETTING_NOTP_LEDGER_QUOTA_BYTES) {
            self.notp_ledger_quota_bytes = parse_bytes(value)
                .with_context(|| format!("reading {SETTING_NOTP_LEDGER_QUOTA_BYTES}"))?;
        }

        if let Some(value) = settings.get(SETTING_AUDIT_RETENTION) {
            self.audit_retention = parse_duration(value)
                .with_context(|| format!("reading {SETTING_AUDIT_RETENTION}"))?;
        }

        if let Some(value) = settings.get(SETTING_CONTROL_KEYS_ENABLED) {
            self.control_keys_enabled = Some(
                parse_bool(value)
                    .with_context(|| format!("reading {SETTING_CONTROL_KEYS_ENABLED}"))?,
            );
        }

        if let Some(value) = settings.get(SETTING_CONTROL_KEYS_DIRECTORY) {
            self.control_keys_directory = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_DATA_KEYS_ENABLED) {
            self.data_keys_enabled = Some(
                parse_bool(value)
                    .with_context(|| format!("reading {SETTING_DATA_KEYS_ENABLED}"))?,
            );
        }

        if let Some(value) = settings.get(SETTING_DATA_KEYS_DIRECTORY) {
            self.data_keys_directory = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_KEYS_ENABLED) {
            self.keys_enabled =
                parse_bool(value).with_context(|| format!("reading {SETTING_KEYS_ENABLED}"))?;
        }

        if let Some(value) = settings.get(SETTING_KEYS_DIRECTORY) {
            self.keys_directory = Some(value.clone());
        }

        if let Some(value) = settings.get(SETTING_KEYS_PUBLISH_AHEAD) {
            self.keys_publish_ahead = parse_duration(value)
                .with_context(|| format!("reading {SETTING_KEYS_PUBLISH_AHEAD}"))?;
            self.keys_lifecycle_declared
                .insert(SETTING_KEYS_PUBLISH_AHEAD);
        }

        if let Some(value) = settings.get(SETTING_KEYS_ROTATE_EVERY) {
            self.keys_rotate_every = parse_duration(value)
                .with_context(|| format!("reading {SETTING_KEYS_ROTATE_EVERY}"))?;
            self.keys_lifecycle_declared
                .insert(SETTING_KEYS_ROTATE_EVERY);
        }

        if let Some(value) = settings.get(SETTING_KEYS_RETAIN) {
            self.keys_retain =
                parse_duration(value).with_context(|| format!("reading {SETTING_KEYS_RETAIN}"))?;
            self.keys_lifecycle_declared.insert(SETTING_KEYS_RETAIN);
        }

        if let Some(value) = settings.get(SETTING_KEYS_MAINTENANCE_INTERVAL) {
            self.keys_maintenance_interval = parse_duration(value)
                .with_context(|| format!("reading {SETTING_KEYS_MAINTENANCE_INTERVAL}"))?;
        }

        for key in &self.declared {
            if let Some(value) = settings.get(key) {
                self.declared_values.insert(key.clone(), value.clone());
            }
        }

        Ok(())
    }
}

/// Assembles the TLS material of one surface out of the flat settings that describe it.
///
/// A certificate without its key — or a key without its certificate — is refused rather than ignored:
/// it is always a half-finished configuration change, and serving in the clear because one line was
/// missing is the failure mode this check exists to prevent.
/// The setting names one surface's TLS block reads, beyond the certificate and key every one has.
struct TlsKeys<'a> {
    client_ca: Option<&'a str>,
    crl: Option<&'a str>,
    allow: Option<&'a str>,
    min_version: &'a str,
}

fn tls_of(
    settings: &BTreeMap<String, String>,
    cert_key: &str,
    key_key: &str,
    keys: TlsKeys<'_>,
    previous: Option<TlsSettings>,
) -> Result<Option<TlsSettings>> {
    let TlsKeys {
        client_ca: client_ca_key,
        crl: crl_key,
        allow: allow_key,
        min_version: min_version_key,
    } = keys;

    let certificate = settings.get(cert_key);
    let key = settings.get(key_key);

    let mut tls = match (certificate, key, previous) {
        (Some(certificate), Some(key), _) => TlsSettings::new(certificate, key),
        (None, None, previous) => return Ok(previous),
        (Some(_), None, _) => bail!("{cert_key} is set but {key_key} is not"),
        (None, Some(_), _) => bail!("{key_key} is set but {cert_key} is not"),
    };

    if let Some(client_ca_key) = client_ca_key
        && let Some(client_ca) = settings.get(client_ca_key)
    {
        tls = tls.with_client_ca(client_ca);
    }

    if let Some(crl_key) = crl_key
        && let Some(crl) = settings.get(crl_key)
    {
        tls = tls.with_crl(crl);
    }

    if let Some(allow_key) = allow_key
        && let Some(value) = settings.get(allow_key)
    {
        tls = tls.with_allow(parse_allowed(value).with_context(|| format!("reading {allow_key}"))?);
    }

    if let Some(value) = settings.get(min_version_key) {
        tls = tls.with_min_version(
            value
                .parse()
                .with_context(|| format!("reading {min_version_key}"))?,
        );
    }

    Ok(Some(tls))
}

/// Reads a setting written as a duration: a plain number of seconds, or one suffixed `ms`, `s`,
/// `m`, `h` or `d`.
///
/// # Why `ms` is one of them
///
/// Most budgets here are human-scale and a second is the smallest unit worth spelling. Group
/// commit is not: it trades a few milliseconds of latency for one `fsync` across a batch, and its
/// own default is [`DEFAULT_EVENTS_GROUP_COMMIT_DELAY`] — five milliseconds. Without `ms` that
/// default could not be written down in the file that configures it, and the shipped configuration
/// saying `5ms` was refused at startup by the parser reading it.
///
/// Zero is refused rather than accepted as "no budget": a shutdown budget of nothing would mean the
/// process kills itself before anything can be released, which nobody configures on purpose.
fn parse_duration(value: &str) -> Result<Duration> {
    const MILLISECOND: u64 = 1;
    const SECOND: u64 = 1_000;
    const MINUTE: u64 = 60 * SECOND;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;

    let value = value.trim();
    // `ms` is tested before `s`, and it has to be: stripping `s` first turns `5ms` into `5m`, which
    // is not a number, and the refusal then quotes a value the author never wrote.
    let millis = value
        .len()
        .checked_sub(2)
        .filter(|at| value.is_char_boundary(*at) && value[*at..].eq_ignore_ascii_case("ms"))
        .map(|at| &value[..at]);
    let (digits, multiplier) = match millis {
        Some(digits) => (digits, MILLISECOND),
        None => match value.strip_suffix(['s', 'S']) {
            Some(digits) => (digits, SECOND),
            None => match value.strip_suffix(['m', 'M']) {
                Some(digits) => (digits, MINUTE),
                None => match value.strip_suffix(['h', 'H']) {
                    Some(digits) => (digits, HOUR),
                    None => match value.strip_suffix(['d', 'D']) {
                        Some(digits) => (digits, DAY),
                        None => (value, SECOND),
                    },
                },
            },
        },
    };

    let amount: u64 = digits.trim().parse().map_err(|_| {
        anyhow!("`{value}` is not a duration: expected something like 5ms, 30s, 2m, 1h or 90d")
    })?;

    if amount == 0 {
        bail!("a duration of zero leaves no budget at all");
    }

    // A retention of a thousand years is a typo — almost always a value in milliseconds that landed
    // in a field counting seconds — and it is worth saying so rather than silently never expiring.
    amount
        .checked_mul(multiplier)
        .map(Duration::from_millis)
        .ok_or_else(|| anyhow!("`{value}` is longer than any deployment outlives"))
}

fn parse_duration_allow_zero(value: &str) -> Result<Duration> {
    let trimmed = value.trim();
    if matches!(
        trimmed,
        "0" | "0s" | "0S" | "0ms" | "0MS" | "0Ms" | "0mS" | "0m" | "0M" | "0h" | "0H" | "0d" | "0D"
    ) {
        return Ok(Duration::ZERO);
    }
    parse_duration(trimmed)
}

fn parse_token_initial_expiry_policy(value: &str) -> Result<TokenInitialExpiryPolicy> {
    match value.trim() {
        "later" => Ok(TokenInitialExpiryPolicy::Later),
        "pic" => Ok(TokenInitialExpiryPolicy::Pic),
        "oauth" => Ok(TokenInitialExpiryPolicy::OAuth),
        other => {
            bail!("`{other}` is not an initial token expiry policy: expected later, pic or oauth")
        }
    }
}

/// Reads a setting written as a count, refusing zero.
///
/// A limit of zero would mean a surface that accepts nothing, which nobody configures on purpose and
/// which looks identical to a typo.
fn parse_count(value: &str) -> Result<u32> {
    let count: u32 = value
        .trim()
        .parse()
        .map_err(|_| anyhow!("`{value}` is not a count"))?;

    if count == 0 {
        bail!("a limit of zero accepts nothing at all");
    }

    Ok(count)
}

/// Reads a setting written as a size: a plain number of bytes, or one suffixed `k`, `M` or `G`.
fn parse_bytes(value: &str) -> Result<u64> {
    const KIB: u64 = 1024;

    let value = value.trim();
    let (digits, multiplier) = match value.strip_suffix(['k', 'K']) {
        Some(digits) => (digits, KIB),
        None => match value.strip_suffix(['m', 'M']) {
            Some(digits) => (digits, KIB * KIB),
            None => match value.strip_suffix(['g', 'G']) {
                Some(digits) => (digits, KIB * KIB * KIB),
                None => (value, 1),
            },
        },
    };

    let amount: u64 = digits
        .trim()
        .trim_end_matches(['b', 'B'])
        .trim()
        .parse()
        .map_err(|_| {
            anyhow!("`{value}` is not a size: expected something like 1M, 512k or 4096")
        })?;

    if amount == 0 {
        bail!("a size of zero accepts no request at all");
    }

    amount
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("`{value}` is larger than any machine has"))
}

/// Reads the list of peers a surface answers, one entry per line.
///
/// Blank lines are skipped, because a YAML list rendered into a block of text ends with one and
/// refusing it would make a correct configuration file an error.
fn parse_allowed(value: &str) -> Result<Vec<AllowedPeer>> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::parse)
        .collect()
}

/// Reports whether an address can only be reached from this host.
///
/// Text rather than a parsed address on purpose: this crate holds no socket types, and the question
/// being asked — *did the deployment write something only this machine can reach* — is answered by
/// what was written. Anything unrecognised is treated as reachable, which is the safe direction to
/// be wrong in.
fn is_loopback(address: &str) -> bool {
    let host = match address.rsplit_once(':') {
        Some((host, _)) => host,
        None => address,
    }
    .trim()
    .trim_start_matches('[')
    .trim_end_matches(']');

    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Reads a setting written as a boolean.
fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => bail!("`{other}` is not a boolean: expected true or false"),
    }
}

fn is_declared_listen_address(key: &str) -> bool {
    key.strip_prefix("PERMGUARD_")
        .is_some_and(|key| key.ends_with("_HTTP_ADDR") || key.ends_with("_GRPC_ADDR"))
}

fn setting_label(key: &str) -> String {
    key.strip_prefix("PERMGUARD_")
        .unwrap_or(key)
        .to_ascii_lowercase()
        .replace('_', ".")
}
