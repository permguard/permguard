// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! ConfigFile class: reads and parses the YAML configuration file named on the command line.
//!
//! The binary never looks for a configuration file on its own. The path always arrives as the
//! positional argument of the invocation, so a container or orchestrator supplies its own default
//! through the command it runs. The file may in turn name a directory of one-realm files
//! (`realms_from`); those are read here too, as part of loading the file that named them.
//!
//! Sections this crate does not know about are kept, not rejected: a build that adds capabilities
//! claims its own sections by name and reads them back with [`ConfigFile::section`]. Whatever nobody
//! claims is reported by [`ConfigFile::reject_unknown_sections`], so a typo is still an error.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_norway::Value;

use crate::config::experimental_setting_key;
use crate::config::{
    DEFAULT_TELEMETRY_ADDR, SETTING_ADMIN_ADDR, SETTING_ADMIN_ALLOW, SETTING_ADMIN_TLS_CERT,
    SETTING_ADMIN_TLS_CLIENT_CA, SETTING_ADMIN_TLS_CRL, SETTING_ADMIN_TLS_KEY,
    SETTING_ADMIN_TLS_MIN_VERSION, SETTING_AUDIT_DIRECTORY, SETTING_AUDIT_PSEUDONYM_ENABLED,
    SETTING_AUDIT_PSEUDONYM_KEY_REF, SETTING_AUDIT_PSEUDONYM_KEY_VERSION, SETTING_AUDIT_REFUSALS,
    SETTING_AUDIT_RETENTION, SETTING_AUDIT_SINK, SETTING_AUTOGENERATE, SETTING_DEVELOPMENT_MODE,
    SETTING_ISSUER, SETTING_KEYS_DIRECTORY, SETTING_KEYS_ENABLED,
    SETTING_KEYS_MAINTENANCE_INTERVAL, SETTING_KEYS_PUBLISH_AHEAD, SETTING_KEYS_RETAIN,
    SETTING_KEYS_ROTATE_EVERY, SETTING_LIMITS_BODY_BYTES, SETTING_LIMITS_CONCURRENT_REQUESTS,
    SETTING_LIMITS_CONNECTION_LIFETIME, SETTING_LIMITS_CONNECTIONS,
    SETTING_LIMITS_CONNECTIONS_PER_PEER, SETTING_LIMITS_HANDSHAKE_TIMEOUT,
    SETTING_LIMITS_HEADER_BYTES, SETTING_LIMITS_HEADER_TIMEOUT, SETTING_LIMITS_PEER_EXEMPT,
    SETTING_LIMITS_REQUEST_TIMEOUT, SETTING_LIMITS_WRITE_STALL_TIMEOUT, SETTING_LOG_FORMAT,
    SETTING_LOG_LEVEL, SETTING_NOTP_COMPRESSION, SETTING_NOTP_LEDGER_QUOTA_BYTES,
    SETTING_NOTP_MAX_BATCH_BYTES, SETTING_NOTP_MAX_BATCH_OBJECTS, SETTING_NOTP_MAX_PUSH_BYTES,
    SETTING_NOTP_MAX_PUSH_OBJECTS, SETTING_OTEL_ENABLED, SETTING_OTEL_ENDPOINT,
    SETTING_OTEL_SAMPLE_RATE, SETTING_PUBLIC_DISCLOSE_BUILD, SETTING_PUBLIC_ERROR_DETAIL,
    SETTING_PUBLIC_GRPC_ADDR, SETTING_PUBLIC_GRPC_ENABLED, SETTING_PUBLIC_HTTP_ADDR,
    SETTING_PUBLIC_HTTP_ENABLED, SETTING_PUBLIC_PATH_PREFIX, SETTING_PUBLIC_TLS_ALLOW,
    SETTING_PUBLIC_TLS_CERT, SETTING_PUBLIC_TLS_CLIENT_CA, SETTING_PUBLIC_TLS_CRL,
    SETTING_PUBLIC_TLS_KEY, SETTING_PUBLIC_TLS_MIN_VERSION, SETTING_SECRETS_DIRECTORY,
    SETTING_SECRETS_ENV_PREFIX, SETTING_SECRETS_PROVIDER, SETTING_SHUTDOWN_TIMEOUT,
    SETTING_TELEMETRY_ADDR, SETTING_TELEMETRY_ADVERTISED_URL, SETTING_TELEMETRY_TLS_CERT,
    SETTING_TELEMETRY_TLS_KEY, SETTING_TELEMETRY_TLS_MIN_VERSION, SETTING_TLS_RELOAD,
    SETTING_TLS_RELOAD_INTERVAL, SETTING_WORKING_DIR,
};
use crate::realm::{
    ClaimMapping, ExchangeProfileClaims, ExchangeProfileConfig, ExchangeProfilePrivileges,
    ExchangeProfileSource, ExchangeTokenValidation, PrivilegeEmit, PrivilegeRule, RealmInput,
    TrustedAttesterConfig,
};

/// The section names this crate parses into typed settings.
const KNOWN_SECTIONS: [&str; 11] = [
    "public",
    "host",
    "telemetry",
    "admin",
    "tls",
    "limits",
    "log",
    "shutdown",
    "operations",
    "notp",
    "experimental",
];

/// The parsed contents of a Permguard configuration file.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
pub struct ConfigFile {
    /// The directory relative paths resolve against. Defaults to the process's working directory.
    #[serde(default)]
    working_dir: Option<String>,
    /// Whether the server may create material it was not given. False unless said otherwise.
    #[serde(default)]
    autogenerate: Option<String>,
    /// Whether this deployment is somebody's laptop. False unless said otherwise.
    #[serde(default)]
    development_mode: Option<String>,
    #[serde(default)]
    public: PublicSection,
    /// The Server Host operations surface. `host` is the name; `telemetry` is accepted as the
    /// older spelling of the same section, because a file that predates the rename is a file
    /// somebody still has.
    #[serde(default, alias = "telemetry")]
    host: TelemetrySection,
    #[serde(default)]
    admin: AdminSection,
    #[serde(default)]
    tls: TransportSection,
    #[serde(default)]
    limits: LimitsSection,
    #[serde(default)]
    log: LogSection,
    #[serde(default)]
    shutdown: ShutdownSection,
    /// The record-keeping subsystem — the keys that seal a trail, the trail itself, and the secret
    /// that pseudonymises it. These are the server's own, and the defaults every realm inherits.
    #[serde(default)]
    operations: OperationsSection,
    /// The NOTP transfer bounds of the git-like store the control plane serves.
    #[serde(default)]
    notp: NotpSection,
    /// Contracts this build carries whose wire and replication shapes have not yet proven stable.
    ///
    /// A block rather than scattered flags, so what is provisional is visible in one place and a
    /// deployment can see everything it has opted into at once.
    #[serde(default)]
    experimental: ExperimentalSection,
    /// The issuers this deployment hosts. A list, not a flat setting, so it is carried as structured
    /// configuration rather than through the layered key/value pipeline — realms come from the file
    /// (and, later, a database), never from a single environment variable.
    #[serde(default)]
    realms: Vec<RealmSection>,
    /// A directory of one-realm files, loaded after the list above. File-only for the same reason
    /// `realms` is: which issuers exist is structured configuration, never an environment variable.
    /// The path resolves against this file's own directory — realm files are configuration, and they
    /// travel with the file that names them.
    #[serde(default, alias = "realmsFrom")]
    realms_from: Option<String>,
    /// Sections outside the typed ones, kept verbatim for whoever claims them.
    #[serde(flatten)]
    sections: BTreeMap<String, Value>,
}

/// One realm as the file declares it, before resolution.
///
/// `name` has no default: a realm without a name is a realm nothing can be routed to, and serde
/// refuses the file rather than inventing one. Every other field — and every nested block — is
/// optional: what a realm does not state, it inherits from the server. The blocks mirror the
/// server's own sections, so a realm overriding its rotation reads exactly like the server setting it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmSection {
    name: String,
    /// How long the PIC Tokens this realm issues stay valid, e.g. `1h`, `30m`.
    #[serde(default, alias = "tokenLifetime")]
    token_lifetime: Option<String>,
    /// Which expiration wins at OAuth-to-PIC initialization: `later`, `pic`, or `oauth`.
    #[serde(default, alias = "tokenInitialExpiryPolicy")]
    token_initial_expiry_policy: Option<String>,
    /// How long cached IdP/attester JWKS remain usable after refresh starts failing.
    #[serde(default, alias = "keyCacheStaleFor")]
    key_cache_stale_for: Option<String>,
    /// Which algorithm this realm signs with: `EdDSA` (default) or `ES256`.
    #[serde(default, alias = "tokenSigningAlgorithm")]
    token_signing_algorithm: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    /// Whether this realm appears in the server's public catalogue. Absent means no.
    #[serde(default)]
    listed: Option<String>,
    /// The realm's token-signing keys — what it signs the tokens it issues with. Its own ring.
    #[serde(default)]
    keys: RealmKeysSection,
    /// The realm's override of the shared `operations` block: the keys that seal its trail, the trail
    /// itself, and its pseudonymisation. Any field absent inherits the server's `operations`.
    #[serde(default)]
    operations: RealmOperationsSection,
    /// Realm-scoped OAuth/PIC Exchange Profiles. Each realm owns its own mappings.
    #[serde(default)]
    exchange_profiles: Vec<ExchangeProfileSection>,
    /// Realm-scoped trusted Proof-of-Relationship attestation issuers.
    #[serde(default)]
    attesters: Vec<TrustedAttesterSection>,
}

/// One Exchange Profile exactly as the file declares it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfileSection {
    id: String,
    source: ExchangeProfileSourceSection,
    claims: ExchangeProfileClaimsSection,
    privileges: ExchangeProfilePrivilegesSection,
    #[serde(default, alias = "onUnmatchedScope")]
    on_unmatched_scope: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfileSourceSection {
    #[serde(alias = "tokenType")]
    token_type: String,
    format: String,
    issuer: String,
    /// Optional: where to reach the provider's discovery document when that address differs from
    /// the issuer identity.
    #[serde(default, alias = "discoveryUrl")]
    discovery_url: Option<String>,
    audience: String,
    #[serde(default)]
    validation: ExchangeTokenValidationSection,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeTokenValidationSection {
    #[serde(default, alias = "allowedAlgorithms")]
    allowed_algorithms: Vec<String>,
    #[serde(default, alias = "requireExpiration")]
    require_expiration: Option<bool>,
    #[serde(default, alias = "requireTokenType")]
    require_token_type: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfileClaimsSection {
    #[serde(default)]
    identity_context: BTreeMap<String, ClaimMappingSection>,
    scopes: ClaimMappingSection,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimMappingSection {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default, rename = "type")]
    value_type: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeProfilePrivilegesSection {
    source: String,
    #[serde(default)]
    rules: Vec<PrivilegeRuleSection>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeRuleSection {
    name: String,
    priority: i32,
    pattern: String,
    emit: PrivilegeEmitSection,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeEmitSection {
    scope: String,
    operation: String,
    #[serde(alias = "resourceType")]
    resource_type: String,
    #[serde(alias = "resourceId")]
    resource_id: String,
}

/// One trusted attestation issuer exactly as the file declares it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedAttesterSection {
    id: String,
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    proof_types: Vec<String>,
    #[serde(default)]
    formats: Vec<String>,
}

impl TrustedAttesterSection {
    fn to_input(&self) -> TrustedAttesterConfig {
        TrustedAttesterConfig {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            jwks_uri: self.jwks_uri.clone(),
            proof_types: self.proof_types.clone(),
            formats: self.formats.clone(),
        }
    }
}

impl ExchangeProfileSection {
    fn to_input(&self) -> ExchangeProfileConfig {
        ExchangeProfileConfig {
            id: self.id.clone(),
            source: ExchangeProfileSource {
                token_type: self.source.token_type.clone(),
                format: self.source.format.clone(),
                issuer: self.source.issuer.clone(),
                discovery_url: self.source.discovery_url.clone(),
                audience: self.source.audience.clone(),
                validation: ExchangeTokenValidation {
                    allowed_algorithms: self.source.validation.allowed_algorithms.clone(),
                    require_expiration: self.source.validation.require_expiration.unwrap_or(false),
                    require_token_type: self.source.validation.require_token_type.clone(),
                },
            },
            claims: ExchangeProfileClaims {
                identity_context: self
                    .claims
                    .identity_context
                    .iter()
                    .map(|(key, mapping)| (key.clone(), mapping.to_input()))
                    .collect(),
                scopes: self.claims.scopes.to_input(),
            },
            privileges: ExchangeProfilePrivileges {
                source: self.privileges.source.clone(),
                rules: self
                    .privileges
                    .rules
                    .iter()
                    .map(PrivilegeRuleSection::to_input)
                    .collect(),
            },
            on_unmatched_scope: self
                .on_unmatched_scope
                .clone()
                .unwrap_or_else(|| "reject".to_owned()),
        }
    }
}

impl ClaimMappingSection {
    fn to_input(&self) -> ClaimMapping {
        ClaimMapping {
            from: self.from.clone(),
            value: self.value.clone(),
            value_type: self.value_type.clone(),
            encoding: self.encoding.clone(),
        }
    }
}

impl PrivilegeRuleSection {
    fn to_input(&self) -> PrivilegeRule {
        PrivilegeRule {
            name: self.name.clone(),
            priority: self.priority,
            pattern: self.pattern.clone(),
            emit: PrivilegeEmit {
                scope: self.emit.scope.clone(),
                operation: self.emit.operation.clone(),
                resource_type: self.emit.resource_type.clone(),
                resource_id: self.emit.resource_id.clone(),
            },
        }
    }
}

/// A realm's override of the shared `operations` block. Each sub-block mirrors the server's, so a
/// realm overriding its audit retention reads exactly like the server setting it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmOperationsSection {
    #[serde(default)]
    keys: RealmKeysSection,
    #[serde(default)]
    audit: RealmAuditSection,
    #[serde(default)]
    secrets: RealmSecretsSection,
}

/// A realm's override of the signing-key lifecycle. Any field absent inherits the server's.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmKeysSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    publish_ahead: Option<String>,
    #[serde(default)]
    rotate_every: Option<String>,
    #[serde(default)]
    retain: Option<String>,
}

/// A realm's override of its audit trail. Any field absent inherits the server's.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmAuditSection {
    #[serde(default)]
    sink: Option<String>,
    #[serde(default)]
    retention: Option<String>,
    #[serde(default)]
    pseudonym: RealmPseudonymSection,
}

/// A realm's override of how audit subjects are pseudonymised.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmPseudonymSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    key_ref: Option<String>,
    #[serde(default)]
    key_version: Option<String>,
}

/// A realm's override of where its secrets come from. Any field absent inherits the server's.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmSecretsSection {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    env_prefix: Option<String>,
}

/// Listener addresses for the user-facing public surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicSection {
    #[serde(default)]
    http: Option<EndpointSection>,
    #[serde(default)]
    grpc: Option<EndpointSection>,
    /// Whether `/version` and gRPC `GetInfo` say which build this is. On by default; a deployment
    /// that would rather not hand fingerprinting material to whoever can open a socket says false.
    #[serde(default)]
    disclose_build: Option<String>,
    /// How much an error says about the inside: `full` or `minimal`. Unset, development mode decides.
    #[serde(default)]
    error_detail: Option<String>,
    /// The public URL this deployment is reached at. Stated, never inferred from a proxy header. It
    /// is the base a realm's `issuer` defaults to (`{url}/realms/<name>`) and, when it carries
    /// a path, what the surface's mount prefix is derived from. The server issues nothing, so this is
    /// a public *address*, not a token issuer.
    #[serde(default)]
    url: Option<String>,
    /// Where the surface is mounted. Empty — the root — unless a proxy forwards a path unstripped.
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default)]
    tls: TlsSection,
}

/// One public protocol surface. A bare string is the legacy spelling for `addr`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum EndpointSection {
    Addr(String),
    Settings(EndpointSettings),
}

impl EndpointSection {
    fn enabled(&self) -> Option<String> {
        match self {
            Self::Addr(_) => None,
            Self::Settings(settings) => settings
                .enabled
                .as_ref()
                .map(EndpointValue::as_setting_value),
        }
    }

    fn addr(&self) -> Option<String> {
        match self {
            Self::Addr(addr) => Some(addr.clone()),
            Self::Settings(settings) => settings.addr.clone(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSettings {
    #[serde(default)]
    enabled: Option<EndpointValue>,
    #[serde(default)]
    addr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum EndpointValue {
    Bool(bool),
    Text(String),
}

impl EndpointValue {
    fn as_setting_value(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Text(value) => value.clone(),
        }
    }
}

/// The certificate a surface presents, and whether it demands one back.
///
/// `client_ca` is the line that turns TLS into mTLS. It is offered on the surfaces where a client has
/// an identity to present, and left out of the telemetry section entirely: a scrape and a kubelet
/// probe have none.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsSection {
    #[serde(default)]
    cert: Option<String>,
    /// Who, of everybody `client_ca` signed, this surface answers. One entry per line-item:
    /// `cn:name`, `dn:subject`, or `sha256:<hex>`. Read on the public surface; the administrative
    /// one has `admin.allow`, and telemetry cannot demand certificates at all.
    #[serde(default)]
    allow: Option<Vec<String>>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    client_ca: Option<String>,
    /// The list the authority publishes of certificates it has taken back.
    #[serde(default)]
    crl: Option<String>,
    #[serde(default)]
    min_version: Option<String>,
}

/// How transport material is treated while the server runs, across every surface at once.
///
/// Not per surface, because the cadence at which files are re-read is a property of the deployment
/// rather than of any one listener, and three copies of it would only ever be three chances to set
/// two of them.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportSection {
    #[serde(default)]
    reload: Option<String>,
    #[serde(default)]
    reload_interval: Option<String>,
}

/// What a surface refuses to spend on any one client.
///
/// Values are kept as text and read as types by `Config`, so an unreadable one is reported the same
/// way whether it came from here, the environment or the command line.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsSection {
    #[serde(default)]
    connections: Option<String>,
    #[serde(default)]
    connections_per_peer: Option<String>,
    #[serde(default)]
    peer_exempt: Option<Vec<String>>,
    #[serde(default)]
    connection_lifetime: Option<String>,
    #[serde(default)]
    write_stall_timeout: Option<String>,
    #[serde(default)]
    concurrent_requests: Option<String>,
    #[serde(default)]
    request_timeout: Option<String>,
    #[serde(default)]
    handshake_timeout: Option<String>,
    #[serde(default)]
    header_timeout: Option<String>,
    #[serde(default)]
    header_bytes: Option<String>,
    #[serde(default)]
    body_bytes: Option<String>,
}

/// The record-keeping subsystem: the ring that seals a trail, the trail, and the pseudonym secret.
///
/// One block at the top level is the server's own and the default every realm inherits; a realm's
/// `operations` override has the same shape.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationsSection {
    #[serde(default)]
    keys: KeysSection,
    #[serde(default)]
    audit: AuditSection,
    #[serde(default)]
    secrets: SecretsSection,
}

/// The keys this deployment signs with and publishes.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    publish_ahead: Option<String>,
    #[serde(default)]
    rotate_every: Option<String>,
    #[serde(default)]
    retain: Option<String>,
    #[serde(default)]
    maintenance_interval: Option<String>,
}

/// The certificate the telemetry surface presents. No client authority, on purpose.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryTlsSection {
    #[serde(default)]
    cert: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    min_version: Option<String>,
}

/// Listener address for the telemetry surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetrySection {
    #[serde(default)]
    addr: Option<String>,
    /// Where the Host surface is reachable from outside, when that is not where it binds.
    #[serde(default)]
    advertised_url: Option<String>,
    #[serde(default)]
    tls: TelemetryTlsSection,
    /// OTLP trace export: off unless the file says otherwise.
    #[serde(default)]
    otel: OtelSection,
}

/// Where spans go, when they go anywhere.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OtelSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    sample_rate: Option<String>,
}

/// Listener address for the administrative surface.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSection {
    #[serde(default)]
    addr: Option<String>,
    #[serde(default)]
    tls: TlsSection,
    /// Who may administer this deployment. A list, because it is one.
    ///
    /// Kept as written and joined for the settings layer, so the same list can arrive from a file as
    /// YAML and from the environment as lines without either form being the special case.
    #[serde(default)]
    allow: Vec<String>,
}

/// How much the build says, and in what shape.
///
/// The values are kept as text here and read as types by `Config`, so an unreadable one is reported
/// with the same wording whether it came from this file, the environment, or the command line.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogSection {
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

/// Where secret material is resolved from.
///
/// Nothing in this section is itself a secret: it says where to look, and the store says what is
/// there.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretsSection {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    env_prefix: Option<String>,
}

/// How long the server is given to put itself away.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShutdownSection {
    #[serde(default)]
    timeout: Option<String>,
}

/// Contracts whose wire and replication shapes have not yet proven stable, by runtime name.
///
/// A map rather than a field per runtime. Which runtimes are provisional is decided by the
/// languages a build carries — each declares itself — so a struct naming them here would have to be
/// edited whenever one is added or graduated, and a deployment opting into a runtime this file did
/// not know about would be refused for the wrong reason.
///
/// A name this build does not carry is not rejected here: the file layer only reads. The startup
/// check reports it, where the list of compiled-in languages is actually available.
type ExperimentalSection = std::collections::BTreeMap<String, ExperimentalRuntimeSection>;

/// Whether this deployment serves one experimental runtime's partitions.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExperimentalRuntimeSection {
    #[serde(default)]
    enabled: Option<String>,
}

/// The NOTP transfer bounds: batch sizes advertised per negotiate, push
/// delta caps, and the per-ledger storage quota.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotpSection {
    #[serde(default)]
    max_batch_bytes: Option<String>,
    #[serde(default)]
    max_batch_objects: Option<String>,
    #[serde(default)]
    max_push_objects: Option<String>,
    #[serde(default)]
    max_push_bytes: Option<String>,
    #[serde(default)]
    ledger_quota_bytes: Option<String>,
    /// Wire compression of NOTP batches: `deflate` (default) or `none`.
    #[serde(default)]
    compression: Option<String>,
}

/// How the audit trail treats the people it records.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditSection {
    /// Where the trail is written: into the log stream, or into files of its own.
    #[serde(default)]
    sink: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    retention: Option<String>,
    /// Whether refused operations are recorded in the trail as well as the log.
    #[serde(default)]
    refusals: Option<String>,
    #[serde(default)]
    pseudonym: PseudonymSection,
}

/// Which secret the pseudonymisation key is, and the version every token names.
///
/// The key itself is not here and never will be: this names it, and the secret store resolves it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PseudonymSection {
    #[serde(default)]
    enabled: Option<String>,
    /// The *name* of the key in the secret store. Never the key.
    #[serde(default)]
    key_ref: Option<String>,
    #[serde(default)]
    key_version: Option<String>,
}

impl ConfigFile {
    /// Reads the file at `path` and parses it as YAML.
    ///
    /// Both a missing file and malformed YAML are reported to the caller; neither is recovered from
    /// by falling back to another location.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading the configuration file {}", path.display()))?;

        let mut file = Self::parse(&text)
            .with_context(|| format!("parsing the configuration file {}", path.display()))?;
        file.gather_realms_from(path)?;

        Ok(file)
    }

    /// Parses configuration-file text.
    pub fn parse(text: &str) -> Result<Self> {
        Ok(serde_norway::from_str(text)?)
    }

    /// Reads the one-realm files in the directory `realms_from` names, appending each to `realms`.
    ///
    /// Every file is one complete realm — the same shape as one `realms:` entry — and is named after
    /// it, so the directory listing is the realm listing. Files load in name order, after the realms
    /// declared inline. Anything surprising refuses to start naming the culprit: a directory that is
    /// not there, a file that does not parse, a file named one thing declaring another, a name
    /// already taken, or a visible entry that is not a realm file at all. Hidden entries are the one
    /// exception — editors and file managers drop them everywhere — and are ignored.
    fn gather_realms_from(&mut self, config_path: &Path) -> Result<()> {
        let Some(named) = self.realms_from.clone() else {
            return Ok(());
        };

        // Relative to the configuration file, not the working directory: realm files are
        // configuration, and they travel with the file that names them.
        let directory = match config_path.parent() {
            Some(parent) if parent != Path::new("") => parent.join(&named),
            _ => PathBuf::from(&named),
        };

        let entries = fs::read_dir(&directory)
            .with_context(|| format!("reading the realms directory {}", directory.display()))?;

        let mut files = Vec::new();
        for entry in entries {
            let entry = entry
                .with_context(|| format!("reading the realms directory {}", directory.display()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();

            if name.starts_with('.') {
                continue;
            }

            let path = entry.path();
            let is_realm_file = path.is_file()
                && matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some("yml" | "yaml")
                );
            if !is_realm_file {
                bail!(
                    "the realms directory {} contains `{name}`, which is not a realm file: every \
                     visible entry is one realm, `<name>.yml`",
                    directory.display()
                );
            }

            files.push(path);
        }

        // Name order, so the directory contributes realms the way its listing reads.
        files.sort();

        for path in files {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("reading the realm file {}", path.display()))?;
            let realm: RealmSection = serde_norway::from_str(&text)
                .with_context(|| format!("parsing the realm file {}", path.display()))?;

            let stem = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            if realm.name != stem {
                bail!(
                    "the realm file {} declares a realm named `{}`: a realm file is named after its \
                     realm, so the directory listing is the realm listing",
                    path.display(),
                    realm.name
                );
            }

            if self
                .realms
                .iter()
                .any(|existing| existing.name == realm.name)
            {
                bail!(
                    "the realm file {} declares `{}` again: a realm name has to be unique, because \
                     it is what decides whose keys sign and whose trail records",
                    path.display(),
                    realm.name
                );
            }

            self.realms.push(realm);
        }

        if self
            .admin
            .tls
            .allow
            .as_ref()
            .is_some_and(|list| !list.is_empty())
        {
            anyhow::bail!(
                "`admin.tls.allow` is not read: the administrative surface's peers are listed under \
                 `admin.allow`"
            );
        }

        Ok(())
    }

    /// The settings this file actually defines, as the configuration-file layer.
    ///
    /// Absent keys are omitted so that they never overwrite a value an earlier layer supplied.
    pub fn settings(&self) -> Vec<(String, String)> {
        // A list is one setting whose value happens to have lines in it, so it travels through the
        // same precedence layers as everything else instead of needing a mechanism of its own.
        let allow = (!self.admin.allow.is_empty()).then(|| self.admin.allow.join("\n"));
        let public_allow = self
            .public
            .tls
            .allow
            .as_ref()
            .filter(|entries| !entries.is_empty())
            .map(|entries| entries.join("\n"));
        let exempt_peers = self
            .limits
            .peer_exempt
            .as_ref()
            .filter(|entries| !entries.is_empty())
            .map(|entries| entries.join(","));

        let candidates = [
            (SETTING_WORKING_DIR, self.working_dir.as_ref()),
            (SETTING_AUTOGENERATE, self.autogenerate.as_ref()),
            (SETTING_DEVELOPMENT_MODE, self.development_mode.as_ref()),
            (SETTING_ISSUER, self.public.url.as_ref()),
            (SETTING_ADMIN_ALLOW, allow.as_ref()),
            (SETTING_TLS_RELOAD, self.tls.reload.as_ref()),
            (
                SETTING_TLS_RELOAD_INTERVAL,
                self.tls.reload_interval.as_ref(),
            ),
            (SETTING_LIMITS_CONNECTIONS, self.limits.connections.as_ref()),
            (
                SETTING_LIMITS_CONNECTIONS_PER_PEER,
                self.limits.connections_per_peer.as_ref(),
            ),
            (SETTING_LIMITS_PEER_EXEMPT, exempt_peers.as_ref()),
            (
                SETTING_LIMITS_CONNECTION_LIFETIME,
                self.limits.connection_lifetime.as_ref(),
            ),
            (
                SETTING_LIMITS_WRITE_STALL_TIMEOUT,
                self.limits.write_stall_timeout.as_ref(),
            ),
            (
                SETTING_LIMITS_CONCURRENT_REQUESTS,
                self.limits.concurrent_requests.as_ref(),
            ),
            (
                SETTING_LIMITS_REQUEST_TIMEOUT,
                self.limits.request_timeout.as_ref(),
            ),
            (
                SETTING_LIMITS_HANDSHAKE_TIMEOUT,
                self.limits.handshake_timeout.as_ref(),
            ),
            (
                SETTING_LIMITS_HEADER_TIMEOUT,
                self.limits.header_timeout.as_ref(),
            ),
            (
                SETTING_LIMITS_HEADER_BYTES,
                self.limits.header_bytes.as_ref(),
            ),
            (SETTING_LIMITS_BODY_BYTES, self.limits.body_bytes.as_ref()),
            (SETTING_PUBLIC_TLS_CRL, self.public.tls.crl.as_ref()),
            (SETTING_PUBLIC_TLS_ALLOW, public_allow.as_ref()),
            (
                SETTING_PUBLIC_DISCLOSE_BUILD,
                self.public.disclose_build.as_ref(),
            ),
            (
                SETTING_PUBLIC_ERROR_DETAIL,
                self.public.error_detail.as_ref(),
            ),
            (SETTING_ADMIN_TLS_CRL, self.admin.tls.crl.as_ref()),
            (
                SETTING_NOTP_MAX_BATCH_BYTES,
                self.notp.max_batch_bytes.as_ref(),
            ),
            (
                SETTING_NOTP_MAX_BATCH_OBJECTS,
                self.notp.max_batch_objects.as_ref(),
            ),
            (
                SETTING_NOTP_MAX_PUSH_OBJECTS,
                self.notp.max_push_objects.as_ref(),
            ),
            (
                SETTING_NOTP_MAX_PUSH_BYTES,
                self.notp.max_push_bytes.as_ref(),
            ),
            (
                SETTING_NOTP_LEDGER_QUOTA_BYTES,
                self.notp.ledger_quota_bytes.as_ref(),
            ),
            (SETTING_NOTP_COMPRESSION, self.notp.compression.as_ref()),
            (SETTING_OTEL_ENABLED, self.host.otel.enabled.as_ref()),
            (SETTING_OTEL_ENDPOINT, self.host.otel.endpoint.as_ref()),
            (
                SETTING_OTEL_SAMPLE_RATE,
                self.host.otel.sample_rate.as_ref(),
            ),
            (SETTING_AUDIT_SINK, self.operations.audit.sink.as_ref()),
            (
                SETTING_AUDIT_REFUSALS,
                self.operations.audit.refusals.as_ref(),
            ),
            (
                SETTING_AUDIT_DIRECTORY,
                self.operations.audit.directory.as_ref(),
            ),
            (
                SETTING_AUDIT_RETENTION,
                self.operations.audit.retention.as_ref(),
            ),
            (SETTING_KEYS_ENABLED, self.operations.keys.enabled.as_ref()),
            (
                SETTING_KEYS_DIRECTORY,
                self.operations.keys.directory.as_ref(),
            ),
            (
                SETTING_KEYS_PUBLISH_AHEAD,
                self.operations.keys.publish_ahead.as_ref(),
            ),
            (
                SETTING_KEYS_ROTATE_EVERY,
                self.operations.keys.rotate_every.as_ref(),
            ),
            (SETTING_KEYS_RETAIN, self.operations.keys.retain.as_ref()),
            (
                SETTING_KEYS_MAINTENANCE_INTERVAL,
                self.operations.keys.maintenance_interval.as_ref(),
            ),
            (SETTING_PUBLIC_PATH_PREFIX, self.public.path_prefix.as_ref()),
            (SETTING_TELEMETRY_ADDR, self.host.addr.as_ref()),
            (
                SETTING_TELEMETRY_ADVERTISED_URL,
                self.host.advertised_url.as_ref(),
            ),
            (SETTING_ADMIN_ADDR, self.admin.addr.as_ref()),
            (SETTING_LOG_LEVEL, self.log.level.as_ref()),
            (SETTING_PUBLIC_TLS_CERT, self.public.tls.cert.as_ref()),
            (SETTING_PUBLIC_TLS_KEY, self.public.tls.key.as_ref()),
            (
                SETTING_PUBLIC_TLS_CLIENT_CA,
                self.public.tls.client_ca.as_ref(),
            ),
            (
                SETTING_PUBLIC_TLS_MIN_VERSION,
                self.public.tls.min_version.as_ref(),
            ),
            (SETTING_ADMIN_TLS_CERT, self.admin.tls.cert.as_ref()),
            (SETTING_ADMIN_TLS_KEY, self.admin.tls.key.as_ref()),
            (
                SETTING_ADMIN_TLS_CLIENT_CA,
                self.admin.tls.client_ca.as_ref(),
            ),
            (
                SETTING_ADMIN_TLS_MIN_VERSION,
                self.admin.tls.min_version.as_ref(),
            ),
            (SETTING_TELEMETRY_TLS_CERT, self.host.tls.cert.as_ref()),
            (SETTING_TELEMETRY_TLS_KEY, self.host.tls.key.as_ref()),
            (
                SETTING_TELEMETRY_TLS_MIN_VERSION,
                self.host.tls.min_version.as_ref(),
            ),
            (SETTING_LOG_FORMAT, self.log.format.as_ref()),
            (SETTING_SHUTDOWN_TIMEOUT, self.shutdown.timeout.as_ref()),
            (
                SETTING_SECRETS_PROVIDER,
                self.operations.secrets.provider.as_ref(),
            ),
            (
                SETTING_SECRETS_DIRECTORY,
                self.operations.secrets.directory.as_ref(),
            ),
            (
                SETTING_SECRETS_ENV_PREFIX,
                self.operations.secrets.env_prefix.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_ENABLED,
                self.operations.audit.pseudonym.enabled.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_KEY_REF,
                self.operations.audit.pseudonym.key_ref.as_ref(),
            ),
            (
                SETTING_AUDIT_PSEUDONYM_KEY_VERSION,
                self.operations.audit.pseudonym.key_version.as_ref(),
            ),
        ];

        let mut settings = Vec::new();

        push_endpoint_settings(
            &mut settings,
            SETTING_PUBLIC_HTTP_ENABLED,
            SETTING_PUBLIC_HTTP_ADDR,
            self.public.http.as_ref(),
        );
        push_endpoint_settings(
            &mut settings,
            SETTING_PUBLIC_GRPC_ENABLED,
            SETTING_PUBLIC_GRPC_ADDR,
            self.public.grpc.as_ref(),
        );

        if matches!(self.public.http, Some(EndpointSection::Addr(_)))
            && self.public.grpc.is_none()
            && let Some(addr) = self.public.http.as_ref().and_then(EndpointSection::addr)
        {
            settings.push((SETTING_PUBLIC_GRPC_ADDR.to_owned(), addr));
        }

        settings.extend(
            candidates
                .into_iter()
                .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone()))),
        );

        // `experimental.<name>.enabled`, one key per runtime the file names. Generated rather than
        // listed, so a build that grows a new provisional runtime needs no edit here.
        settings.extend(self.experimental.iter().filter_map(|(name, section)| {
            section
                .enabled
                .as_ref()
                .map(|enabled| (experimental_setting_key(name), enabled.clone()))
        }));

        // The Server Host operations surface is the one interface every deployment exposes
        // identically, so a file that says nothing about it gets the role port rather than no
        // surface. Only a file that was actually loaded carries the default — a config assembled
        // in code keeps saying exactly what it says — and a later layer (the environment, the
        // command line) still overrides it like any other file value. Opting out is explicit:
        // `host.addr: off`.
        if self.host.addr.is_none() {
            settings.push((
                SETTING_TELEMETRY_ADDR.to_owned(),
                DEFAULT_TELEMETRY_ADDR.to_owned(),
            ));
        }

        settings
    }

    /// Returns a section this crate does not parse, for whoever declared it.
    pub fn section(&self, name: &str) -> Option<&Value> {
        self.sections.get(name)
    }

    /// Returns the realms this file declares, as raw overrides to be resolved against the server.
    ///
    /// No value is parsed here — a duration or a boolean is read by the same rules the server uses,
    /// which live where the server configuration is resolved. This only carries what the file said,
    /// in the file's order, so the catalogue and the log list realms the way an operator wrote them.
    pub fn realms(&self) -> Vec<RealmInput> {
        self.realms
            .iter()
            .map(|realm| RealmInput {
                token_lifetime: realm.token_lifetime.clone(),
                token_initial_expiry_policy: realm.token_initial_expiry_policy.clone(),
                key_cache_stale_for: realm.key_cache_stale_for.clone(),
                token_signing_algorithm: realm.token_signing_algorithm.clone(),
                name: realm.name.clone(),
                issuer: realm.issuer.clone(),
                listed: realm.listed.clone(),
                token_keys_enabled: realm.keys.enabled.clone(),
                token_keys_publish_ahead: realm.keys.publish_ahead.clone(),
                token_keys_rotate_every: realm.keys.rotate_every.clone(),
                token_keys_retain: realm.keys.retain.clone(),
                operations_keys_enabled: realm.operations.keys.enabled.clone(),
                operations_keys_publish_ahead: realm.operations.keys.publish_ahead.clone(),
                operations_keys_rotate_every: realm.operations.keys.rotate_every.clone(),
                operations_keys_retain: realm.operations.keys.retain.clone(),
                audit_sink: realm.operations.audit.sink.clone(),
                audit_retention: realm.operations.audit.retention.clone(),
                audit_pseudonym_enabled: realm.operations.audit.pseudonym.enabled.clone(),
                audit_pseudonym_key_ref: realm.operations.audit.pseudonym.key_ref.clone(),
                audit_pseudonym_key_version: realm.operations.audit.pseudonym.key_version.clone(),
                secrets_provider: realm.operations.secrets.provider.clone(),
                secrets_env_prefix: realm.operations.secrets.env_prefix.clone(),
                exchange_profiles: realm
                    .exchange_profiles
                    .iter()
                    .map(ExchangeProfileSection::to_input)
                    .collect(),
                trusted_attesters: realm
                    .attesters
                    .iter()
                    .map(TrustedAttesterSection::to_input)
                    .collect(),
            })
            .collect()
    }

    /// Returns every section outside the typed ones, in file-independent order.
    pub fn extra_sections(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.sections
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Fails when the file declares a section neither this crate nor `claimed` accounts for.
    ///
    /// This is what keeps a misspelled top-level section an error instead of a silently ignored one.
    pub fn reject_unknown_sections<'a, I>(&self, claimed: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let claimed: Vec<&str> = claimed.into_iter().collect();

        let unknown: Vec<&str> = self
            .sections
            .keys()
            .map(String::as_str)
            .filter(|name| !claimed.contains(name))
            .collect();

        if unknown.is_empty() {
            return Ok(());
        }

        let known = KNOWN_SECTIONS
            .iter()
            .copied()
            .chain(claimed)
            .collect::<Vec<_>>()
            .join(", ");

        // One section moved, and a file that predates the move is a file somebody
        // still has: say where it went rather than only that it is unknown.
        let moved = if unknown.contains(&"sync") {
            " `sync` moved under `dataPlane`: mirroring is the data plane's own business, and a \
             control plane has nothing to mirror."
        } else {
            ""
        };

        bail!(
            "the configuration file declares unknown section(s): {}. Known sections: {known}.{moved}",
            unknown.join(", ")
        );
    }
}

fn push_endpoint_settings(
    settings: &mut Vec<(String, String)>,
    enabled_key: &str,
    addr_key: &str,
    endpoint: Option<&EndpointSection>,
) {
    let Some(endpoint) = endpoint else {
        return;
    };

    if let Some(enabled) = endpoint.enabled() {
        settings.push((enabled_key.to_owned(), enabled));
    }

    if let Some(addr) = endpoint.addr() {
        settings.push((addr_key.to_owned(), addr));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const FULL: &str = "public:\n  http: 0.0.0.0:5556\ntelemetry:\n  addr: 0.0.0.0:5558\nadmin:\n  addr: 127.0.0.1:5557\n";

    fn settings_of(text: &str) -> Vec<(String, String)> {
        ConfigFile::parse(text).expect("the file parses").settings()
    }

    #[test]
    fn test_parse_reads_every_documented_section() {
        let file = ConfigFile::parse(FULL).expect("the file parses");

        assert_eq!(
            file.public.http.as_ref().and_then(EndpointSection::addr),
            Some("0.0.0.0:5556".to_owned())
        );
        assert_eq!(file.host.addr.as_deref(), Some("0.0.0.0:5558"));
        assert_eq!(file.admin.addr.as_deref(), Some("127.0.0.1:5557"));
    }

    #[test]
    fn test_settings_yield_one_pair_per_declared_value() {
        assert_eq!(
            settings_of(FULL),
            vec![
                (
                    SETTING_PUBLIC_HTTP_ADDR.to_owned(),
                    "0.0.0.0:5556".to_owned()
                ),
                (
                    SETTING_PUBLIC_GRPC_ADDR.to_owned(),
                    "0.0.0.0:5556".to_owned()
                ),
                (SETTING_TELEMETRY_ADDR.to_owned(), "0.0.0.0:5558".to_owned()),
                (SETTING_ADMIN_ADDR.to_owned(), "127.0.0.1:5557".to_owned()),
            ]
        );
    }

    #[test]
    fn test_absent_sections_yield_no_settings_except_the_host_default() {
        // The Server Host surface is the one setting a silent file still carries: every other
        // absent key stays absent, so it can never overwrite an earlier layer.
        assert!(
            settings_of("public:\n  http: 0.0.0.0:5556\n")
                .iter()
                .all(|(key, _)| key == SETTING_PUBLIC_HTTP_ADDR
                    || key == SETTING_PUBLIC_GRPC_ADDR
                    || key == SETTING_TELEMETRY_ADDR)
        );
        assert_eq!(
            settings_of("{}"),
            vec![(
                SETTING_TELEMETRY_ADDR.to_owned(),
                DEFAULT_TELEMETRY_ADDR.to_owned()
            )]
        );
    }

    #[test]
    fn test_a_silent_file_gets_the_host_role_port() {
        let settings = settings_of("public:\n  http: 0.0.0.0:5556\n");
        assert!(
            settings.contains(&(
                SETTING_TELEMETRY_ADDR.to_owned(),
                DEFAULT_TELEMETRY_ADDR.to_owned()
            )),
            "a file that says nothing about the Host surface serves it on the role port"
        );
    }

    #[test]
    fn test_the_host_surface_opt_out_is_explicit_and_carried() {
        // `off` travels as written; `Config::telemetry_addr` is what reads it back as no address.
        let settings = settings_of("host:\n  addr: off\n");
        assert!(
            settings.contains(&(SETTING_TELEMETRY_ADDR.to_owned(), "off".to_owned())),
            "{settings:?}"
        );
        assert_eq!(
            settings
                .iter()
                .filter(|(key, _)| key == SETTING_TELEMETRY_ADDR)
                .count(),
            1,
            "an explicit value suppresses the default"
        );
    }

    #[test]
    fn test_the_host_section_is_the_telemetry_section() {
        // Same section, two spellings: `host` is the name, `telemetry` the accepted older one.
        let renamed = settings_of("host:\n  addr: 0.0.0.0:6000\n");
        let dated = settings_of("telemetry:\n  addr: 0.0.0.0:6000\n");
        assert_eq!(renamed, dated);
    }

    #[test]
    fn test_the_host_advertised_url_is_carried() {
        let settings =
            settings_of("host:\n  addr: 0.0.0.0:5443\n  advertised_url: https://ops.example.com\n");
        assert!(settings.contains(&(
            SETTING_TELEMETRY_ADVERTISED_URL.to_owned(),
            "https://ops.example.com".to_owned()
        )));
    }

    #[test]
    fn test_public_protocol_surfaces_can_be_configured_independently() {
        assert_eq!(
            settings_of(
                "public:\n  http:\n    enabled: false\n  grpc:\n    enabled: true\n    addr: 0.0.0.0:5557\n"
            ),
            vec![
                (SETTING_PUBLIC_HTTP_ENABLED.to_owned(), "false".to_owned()),
                (SETTING_PUBLIC_GRPC_ENABLED.to_owned(), "true".to_owned()),
                (
                    SETTING_PUBLIC_GRPC_ADDR.to_owned(),
                    "0.0.0.0:5557".to_owned()
                ),
                (
                    SETTING_TELEMETRY_ADDR.to_owned(),
                    DEFAULT_TELEMETRY_ADDR.to_owned()
                ),
            ]
        );
    }

    #[test]
    fn test_realm_key_cache_stale_window_is_read() {
        let file = ConfigFile::parse(
            "realms:\n  - name: acme\n    tokenLifetime: 1h\n    tokenInitialExpiryPolicy: oauth\n    keyCacheStaleFor: 10m\n",
        )
        .expect("the file parses");

        assert_eq!(
            file.realms()[0].token_initial_expiry_policy.as_deref(),
            Some("oauth")
        );
        assert_eq!(file.realms()[0].key_cache_stale_for.as_deref(), Some("10m"));
    }

    #[test]
    fn test_unknown_key_is_rejected() {
        let unknown_section = ConfigFile::parse("public:\n  http: 0.0.0.0:5556\nnope: 1\n")
            .expect("an unclaimed section still parses");
        assert!(unknown_section.reject_unknown_sections([]).is_err());

        assert!(ConfigFile::parse("public:\n  htpp: 0.0.0.0:5556\n").is_err());
    }

    #[test]
    fn test_tls_material_is_read_from_the_section_of_the_surface_it_belongs_to() {
        let settings = settings_of(
            "public:\n  http: 0.0.0.0:5556\n  tls:\n    cert: /tls/public.pem\n    key: /tls/public.key\n\
             admin:\n  addr: 127.0.0.1:5557\n  tls:\n    cert: /tls/admin.pem\n    key: /tls/admin.key\n    client_ca: /tls/clients.pem\n",
        );

        assert!(settings.contains(&(
            SETTING_PUBLIC_TLS_CERT.to_owned(),
            "/tls/public.pem".to_owned()
        )));
        assert!(settings.contains(&(
            SETTING_ADMIN_TLS_CLIENT_CA.to_owned(),
            "/tls/clients.pem".to_owned()
        )));
    }

    #[test]
    fn test_the_telemetry_section_offers_no_client_authority() {
        // `client_ca` under telemetry is a typo or a misunderstanding; either way the file is refused
        // rather than quietly serving without the mutual authentication somebody thought they asked
        // for.
        assert!(
            ConfigFile::parse(
                "telemetry:\n  addr: 0.0.0.0:5558\n  tls:\n    client_ca: /tls/clients.pem\n"
            )
            .is_err()
        );
    }

    #[test]
    fn test_malformed_yaml_is_rejected() {
        assert!(ConfigFile::parse("public: [unclosed\n").is_err());
    }

    #[test]
    fn test_a_claimed_section_is_kept_and_readable() {
        let file =
            ConfigFile::parse("public:\n  http: 0.0.0.0:5556\nsso:\n  issuer: https://idp\n")
                .expect("the file parses");

        assert!(file.reject_unknown_sections(["sso"]).is_ok());
        assert!(file.section("sso").is_some());
        assert_eq!(
            file.extra_sections()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            vec!["sso"]
        );
        // Claiming a section does not change the typed settings the file contributes.
        assert_eq!(
            file.settings(),
            vec![
                (
                    SETTING_PUBLIC_HTTP_ADDR.to_owned(),
                    "0.0.0.0:5556".to_owned()
                ),
                (
                    SETTING_PUBLIC_GRPC_ADDR.to_owned(),
                    "0.0.0.0:5556".to_owned()
                ),
                (
                    SETTING_TELEMETRY_ADDR.to_owned(),
                    DEFAULT_TELEMETRY_ADDR.to_owned()
                ),
            ]
        );
    }

    #[test]
    fn test_an_unclaimed_section_is_named_in_the_error() {
        let file = ConfigFile::parse("sso:\n  issuer: https://idp\n").expect("the file parses");

        let error = file
            .reject_unknown_sections([])
            .expect_err("nobody claimed the section");
        assert!(format!("{error}").contains("sso"));
    }

    #[test]
    fn test_load_reports_a_missing_file_instead_of_falling_back() {
        let error = ConfigFile::load(Path::new("/nonexistent/permguard/config.yml"))
            .expect_err("a missing file is an error");

        assert!(format!("{error:#}").contains("/nonexistent/permguard/config.yml"));
    }

    /// A scratch root of this test's own, never shared with a previous run.
    ///
    /// Unique per call, deliberately: a deterministic path is a path a killed
    /// run leaves behind — sometimes as something that is not a directory —
    /// and the next run then fails on the leftover rather than on the code
    /// under test. Uniqueness costs nothing and removes the whole class.
    fn scratch_root(case: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!(
            "permguard-realms-from-{case}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("creating the scratch root");

        root
    }

    /// Writes a configuration naming `realms_from: realms.d`, plus one file per `(name, text)` in
    /// that directory, in a scratch root of its own. Returns the configuration file's path.
    fn realms_from_fixture(case: &str, realm_files: &[(&str, &str)], config_body: &str) -> PathBuf {
        let root = scratch_root(case);
        fs::create_dir_all(root.join("realms.d")).expect("creating the realms directory");

        for (name, text) in realm_files {
            fs::write(root.join("realms.d").join(name), text).expect("writing a realm file");
        }

        let config = root.join("config.yml");
        fs::write(&config, format!("realms_from: realms.d\n{config_body}"))
            .expect("writing the configuration under test");

        config
    }

    #[test]
    fn test_realm_files_load_in_name_order_after_the_inline_realms() {
        // Two spellings, one list: the inline realms first, then the directory's in name order —
        // deterministic, so the catalogue never depends on what order a filesystem feels like.
        let config = realms_from_fixture(
            "order",
            &[
                ("beta.yml", "name: beta\n"),
                ("alpha.yml", "name: alpha\ntoken_lifetime: 2h\n"),
            ],
            "realms:\n  - name: acme\n",
        );

        let realms = ConfigFile::load(&config).expect("the file loads").realms();

        let names: Vec<&str> = realms.iter().map(|realm| realm.name.as_str()).collect();
        assert_eq!(names, ["acme", "alpha", "beta"]);
        assert_eq!(realms[1].token_lifetime.as_deref(), Some("2h"));
    }

    #[test]
    fn test_a_realm_file_is_named_after_the_realm_it_declares() {
        // The directory listing is the realm listing. A file named one thing declaring another
        // makes the listing lie, so it is refused rather than trusted.
        let config = realms_from_fixture("misnamed", &[("acme.yml", "name: globex\n")], "");

        let error = ConfigFile::load(&config).expect_err("the mismatch is an error");

        let message = format!("{error:#}");
        assert!(message.contains("acme.yml"), "{message}");
        assert!(message.contains("globex"), "{message}");
    }

    #[test]
    fn test_a_realm_declared_inline_and_as_a_file_is_refused() {
        let config = realms_from_fixture(
            "duplicate",
            &[("acme.yml", "name: acme\n")],
            "realms:\n  - name: acme\n",
        );

        let error = ConfigFile::load(&config).expect_err("the duplicate is an error");

        let message = format!("{error:#}");
        assert!(message.contains("acme"), "{message}");
        assert!(message.contains("unique"), "{message}");
    }

    #[test]
    fn test_a_missing_realms_directory_is_an_error() {
        // The file names a directory that is not there: the configuration lies about the
        // deployment, and a lie is refused rather than quietly shrugged into zero realms.
        let root = scratch_root("missing");
        let config = root.join("config.yml");
        fs::write(&config, "realms_from: realms.d\n").expect("writing the configuration");

        let error = ConfigFile::load(&config).expect_err("the missing directory is an error");

        assert!(format!("{error:#}").contains("realms.d"));
    }

    #[test]
    fn test_a_realm_file_that_does_not_parse_is_named_in_the_error() {
        let config = realms_from_fixture(
            "unparsable",
            &[("acme.yml", "name: acme\nno_such_field: 1\n")],
            "",
        );

        let error = ConfigFile::load(&config).expect_err("the unknown field is an error");

        assert!(format!("{error:#}").contains("acme.yml"));
    }

    #[test]
    fn test_a_stray_file_in_the_realms_directory_is_refused() {
        // A visible entry that is not a realm file would be a realm the listing shows and the
        // server ignores — the silent kind of wrong. Refused, naming it.
        let config = realms_from_fixture(
            "stray",
            &[("acme.yml", "name: acme\n"), ("notes.txt", "scratch\n")],
            "",
        );

        let error = ConfigFile::load(&config).expect_err("the stray file is an error");

        assert!(format!("{error:#}").contains("notes.txt"));
    }

    #[test]
    fn test_hidden_entries_in_the_realms_directory_are_ignored() {
        // Editors and file managers drop hidden files everywhere; a lab that refuses to start over
        // a .DS_Store is not strict, it is broken.
        let config = realms_from_fixture(
            "hidden",
            &[("acme.yml", "name: acme\n"), (".DS_Store", "junk")],
            "",
        );

        let realms = ConfigFile::load(&config).expect("the file loads").realms();

        assert_eq!(realms.len(), 1);
        assert_eq!(realms[0].name, "acme");
    }
}
