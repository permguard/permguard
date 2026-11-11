// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The authorization model (WP-2.4): resources, selectors, principals, the actor a request acts
//! as, and the grants that decide.
//!
//! ```text
//! Resource = host
//!          | plane/<plane>
//!          | plane/<plane>/zone/<zone_id>
//!          | plane/<plane>/zone/<zone_id>/ledger/<ledger_id>
//!
//! Selector = an exact Resource prefix, optionally ending in /*
//! contains(selector, resource) ⇔ selector is a component-aligned prefix of resource
//!
//! authorize(actor, operation, resource, type) =
//!     authenticated(actor)
//!     ∧ ∃ active grant: grant.principal = actor.principal
//!                     ∧ grant.operation = operation
//!                     ∧ contains(grant.selector, resource)
//!                     ∧ grant.resource_type ∈ { type, "*" }
//! ```
//!
//! There are no deny grants: absence of an allow is deny. A request names one concrete resource;
//! wildcards exist only in grants. The model is pure data here, so every crate agrees on what a
//! selector contains; the store that holds the grants, the mapper that produces an actor and the
//! handle a Plane authorizes through are `permguard-host`'s.
//!
//! [`ActorContext`] is immutable after the transport boundary and is the sole input to
//! authorization: one `authorization_principal`, 1 to 512 bytes of UTF-8 without NUL or control
//! characters, used byte for byte. A certificate's common name or distinguished name is a label,
//! never a principal.

use std::fmt;

use crate::AccessDenial;

/// The operations this release's routes check, closed: a grant naming another is refused at
/// issue and ignored at load (owner decision, 2026-10-06). A later package adds the operations
/// its routes check.
pub mod operations {
    /// Read the catalog of zones and ledgers.
    pub const CATALOG_READ: &str = "catalog.read";
    /// Create, rename and delete zones and ledgers.
    pub const CATALOG_WRITE: &str = "catalog.write";
    /// Push policy to a ledger over NOTP.
    pub const POLICY_PUSH: &str = "policy.push";
    /// Ask a Data Plane for a decision.
    pub const DECISION_EVALUATE: &str = "decision.evaluate";
    /// Submit an occurrence to the temporal interface.
    pub const EVENT_SUBMIT: &str = "event.submit";
    /// Read the Authority Plane's service accounts, their scopes and access keys (`2-security/5`).
    pub const ACCOUNTS_READ: &str = "accounts.read";
    /// Create, change, suspend and delete service accounts, set their scopes, make and delete
    /// their access keys (`2-security/5`).
    pub const ACCOUNTS_WRITE: &str = "accounts.write";
    /// List the tokens the Authority Plane issued (`2-security/5`).
    pub const TOKENS_READ: &str = "tokens.read";
    /// Revoke a token the Authority Plane issued (`2-security/5`).
    pub const TOKENS_REVOKE: &str = "tokens.revoke";
    /// Read the lifecycle of the Host, its Planes and its services: `GET /host/v1/status`
    /// (WP-2.5, owner decision of 2026-10-06).
    pub const LIFECYCLE_READ: &str = "lifecycle.read";
    /// List the key rings the Host composes: `GET /host/v1/keys`. One ring's public set is
    /// public keys, served without a grant.
    pub const KEYS_READ: &str = "keys.read";
    /// Read the effective configuration and its revisions.
    pub const CONFIG_READ: &str = "config.read";
    /// Read the Host identity (WP-2.2) and its ring bindings (WP-2.3).
    pub const IDENTITY_READ: &str = "identity.read";
    /// Rotate the Host identity, and reset it when the memberships exist: the "identity grant"
    /// of the blueprint, granted only explicitly (WP-2.2, owner decision of 2026-10-08).
    pub const IDENTITY_ADMIN: &str = "identity.admin";
    /// Rotate and revoke the Host's key rings, `host.identity` excepted: the "key grant" of the
    /// blueprint, granted only explicitly (WP-3.1, owner decision of 2026-10-08).
    pub const KEYS_ADMIN: &str = "keys.admin";
    /// List and read the memberships and their invitations (WP-4.1).
    pub const MEMBERSHIP_READ: &str = "membership.read";
    /// Invite, approve, reject, suspend, resume, fence and revoke memberships, and join a
    /// coordinator: the "membership grant" of the blueprint, granted only explicitly (WP-4.1).
    pub const MEMBERSHIP_ADMIN: &str = "membership.admin";
    /// Read the audit trails of a resource: their records, checkpoints and exports (WP-3.7,
    /// owner decision of 2026-10-11).
    pub const AUDIT_READ: &str = "audit.read";
    /// Read the Host's streams: their descriptors, frontiers, records, signers, subscriptions,
    /// gaps and anchors (WP-5.7).
    pub const STREAMS_READ: &str = "streams.read";
    /// Read the decision and event evidence the Control Plane serves, on the exact ledger
    /// (WP-6.3c, `1-control-plane.md` plane public API).
    pub const EVIDENCE_READ: &str = "evidence.read";
    /// Prepare, finalize and abort an application-consistent backup of the Host's volume
    /// (WP-7.8, `6-command-line/2-command-line-commands.md` backup).
    pub const BACKUP_MANAGE: &str = "backup.manage";
    /// List the snapshot manifests the Host knows (WP-7.8).
    pub const BACKUP_READ: &str = "backup.read";
    /// Plan and run a garbage-collection job on the Host API, on the scope it sweeps (WP-7.11b,
    /// `6-command-line/2-command-line-commands.md` garbage collection).
    pub const GC_MANAGE: &str = "gc.manage";

    /// Every registered operation.
    pub const ALL: &[&str] = &[
        CATALOG_READ,
        CATALOG_WRITE,
        POLICY_PUSH,
        DECISION_EVALUATE,
        EVENT_SUBMIT,
        ACCOUNTS_READ,
        ACCOUNTS_WRITE,
        TOKENS_READ,
        TOKENS_REVOKE,
        LIFECYCLE_READ,
        KEYS_READ,
        CONFIG_READ,
        IDENTITY_READ,
        IDENTITY_ADMIN,
        KEYS_ADMIN,
        MEMBERSHIP_READ,
        MEMBERSHIP_ADMIN,
        AUDIT_READ,
        STREAMS_READ,
        EVIDENCE_READ,
        BACKUP_MANAGE,
        BACKUP_READ,
        GC_MANAGE,
    ];

    /// Whether `operation` is registered.
    pub fn is_registered(operation: &str) -> bool {
        ALL.contains(&operation)
    }
}

/// The resource types a grant may name, closed like the operations.
pub mod resource_types {
    pub const HOST: &str = "host";
    pub const PLANE: &str = "plane";
    pub const ZONE: &str = "zone";
    pub const LEDGER: &str = "ledger";
    /// Every type: the one wildcard a grant may carry.
    pub const ANY: &str = "*";

    /// Every registered type, the wildcard included.
    pub const ALL: &[&str] = &[HOST, PLANE, ZONE, LEDGER, ANY];

    /// Whether `resource_type` is registered.
    pub fn is_registered(resource_type: &str) -> bool {
        ALL.contains(&resource_type)
    }
}

/// The longest identifier a resource component may be: a canonical UUID with room to spare.
const MAX_COMPONENT: usize = 128;

/// One concrete resource, always relative to the Host that authorizes it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Resource {
    Host,
    Plane {
        plane: String,
    },
    Zone {
        plane: String,
        zone_id: String,
    },
    Ledger {
        plane: String,
        zone_id: String,
        ledger_id: String,
    },
}

impl Resource {
    /// The Host itself.
    pub fn host() -> Self {
        Self::Host
    }

    /// A Plane, by its id.
    pub fn plane(plane: impl Into<String>) -> Self {
        Self::Plane {
            plane: plane.into(),
        }
    }

    /// A zone of a Plane, by their ids.
    pub fn zone(plane: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self::Zone {
            plane: plane.into(),
            zone_id: zone_id.into(),
        }
    }

    /// A ledger of a zone of a Plane, by their ids.
    pub fn ledger(
        plane: impl Into<String>,
        zone_id: impl Into<String>,
        ledger_id: impl Into<String>,
    ) -> Self {
        Self::Ledger {
            plane: plane.into(),
            zone_id: zone_id.into(),
            ledger_id: ledger_id.into(),
        }
    }

    /// The registered type of this resource.
    pub fn resource_type(&self) -> &'static str {
        match self {
            Self::Host => resource_types::HOST,
            Self::Plane { .. } => resource_types::PLANE,
            Self::Zone { .. } => resource_types::ZONE,
            Self::Ledger { .. } => resource_types::LEDGER,
        }
    }

    /// The Plane this resource belongs to; `None` for the Host.
    pub fn plane_id(&self) -> Option<&str> {
        match self {
            Self::Host => None,
            Self::Plane { plane } | Self::Zone { plane, .. } | Self::Ledger { plane, .. } => {
                Some(plane)
            }
        }
    }

    /// The path components, in order.
    fn components(&self) -> Vec<&str> {
        match self {
            Self::Host => vec!["host"],
            Self::Plane { plane } => vec!["plane", plane],
            Self::Zone { plane, zone_id } => vec!["plane", plane, "zone", zone_id],
            Self::Ledger {
                plane,
                zone_id,
                ledger_id,
            } => vec!["plane", plane, "zone", zone_id, "ledger", ledger_id],
        }
    }

    /// Reads a resource from its text form, refusing anything that is not exactly one of the
    /// six shapes.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let parts: Vec<&str> = text.split('/').collect();
        for part in &parts {
            component(part)?;
        }
        match parts.as_slice() {
            ["host"] => Ok(Self::Host),
            ["plane", plane] => Ok(Self::plane(*plane)),
            ["plane", plane, "zone", zone] => Ok(Self::zone(*plane, *zone)),
            ["plane", plane, "zone", zone, "ledger", ledger] => {
                Ok(Self::ledger(*plane, *zone, *ledger))
            }
            _ => Err(ParseError::Shape(text.to_owned())),
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.components().join("/"))
    }
}

/// Why a resource, selector or principal did not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Not one of the shapes the tree allows: a diagonal selector, a wildcard inside a path, an
    /// unknown level.
    Shape(String),
    /// A component is empty, too long, or holds a character outside `A-Z a-z 0-9 - _ . :`.
    Component(String),
    /// A principal is empty, over 512 bytes, or holds NUL or a control character.
    Principal(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(text) => write!(
                f,
                "`{text}` is not a resource: expected `host`, `plane/<p>`, \
                 `plane/<p>/zone/<id>` or `plane/<p>/zone/<id>/ledger/<id>`, optionally ending in `/*`"
            ),
            Self::Component(text) => write!(
                f,
                "`{text}` is not a resource component: 1 to {MAX_COMPONENT} characters of \
                 `A-Z a-z 0-9 - _ . :`"
            ),
            Self::Principal(reason) => write!(f, "not a principal: {reason}"),
        }
    }
}

impl std::error::Error for ParseError {}

fn component(part: &str) -> Result<(), ParseError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':');
    if part.is_empty() || part.len() > MAX_COMPONENT || !part.chars().all(allowed) {
        return Err(ParseError::Component(part.to_owned()));
    }
    Ok(())
}

/// An exact resource prefix, optionally covering everything below it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selector {
    prefix: Resource,
    descendants: bool,
}

impl Selector {
    /// Exactly `resource`, and nothing below it.
    pub fn exactly(resource: Resource) -> Self {
        Self {
            prefix: resource,
            descendants: false,
        }
    }

    /// `resource` and everything below it: the `/*` form.
    pub fn under(resource: Resource) -> Self {
        Self {
            prefix: resource,
            descendants: true,
        }
    }

    /// Reads a selector from its text form: a resource, optionally ending in `/*`.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        match text.strip_suffix("/*") {
            Some(prefix) => Resource::parse(prefix).map(Self::under),
            None => Resource::parse(text).map(Self::exactly),
        }
    }

    /// The resource this selector starts at.
    pub fn prefix(&self) -> &Resource {
        &self.prefix
    }

    /// Whether it covers what lies below the prefix.
    pub fn covers_descendants(&self) -> bool {
        self.descendants
    }

    /// Whether `resource` is this selector's prefix, or below it when the selector descends.
    pub fn contains(&self, resource: &Resource) -> bool {
        if &self.prefix == resource {
            return true;
        }
        if !self.descendants {
            return false;
        }
        let prefix = self.prefix.components();
        let resource = resource.components();
        resource.len() > prefix.len() && resource[..prefix.len()] == prefix[..]
    }

    /// Whether anything this selector covers lies at or under `resource`: the selector's prefix
    /// is `resource` or below it.
    pub fn reaches_under(&self, resource: &Resource) -> bool {
        let prefix = self.prefix.components();
        let resource = resource.components();
        prefix.len() >= resource.len() && prefix[..resource.len()] == resource[..]
    }

    /// Whether this selector covers `resource` and everything below it whole.
    pub fn covers_whole(&self, resource: &Resource) -> bool {
        self.descendants && self.contains(resource)
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)?;
        if self.descendants {
            f.write_str("/*")?;
        }
        Ok(())
    }
}

/// Whether a grant of `operation` on `selector` can ever allow anything: the selector contains at
/// least one resource of the kinds the operation applies to (iteration 02, `2-security/6` Grant
/// coherence). An unregistered operation fits nothing.
pub fn operation_fits(operation: &str, selector: &Selector) -> bool {
    use operations as op;
    let prefix = selector.prefix();
    let host = matches!(prefix, Resource::Host);
    let plane = |wanted: Option<&str>| match prefix.plane_id() {
        Some(plane) => wanted.is_none_or(|wanted| wanted == plane),
        None => false,
    };
    match operation {
        op::ACCOUNTS_READ | op::ACCOUNTS_WRITE | op::TOKENS_READ | op::TOKENS_REVOKE => {
            plane(Some("authority"))
        }
        op::IDENTITY_READ
        | op::IDENTITY_ADMIN
        | op::KEYS_ADMIN
        | op::MEMBERSHIP_READ
        | op::MEMBERSHIP_ADMIN
        | op::CONFIG_READ
        | op::LIFECYCLE_READ
        | op::BACKUP_READ
        | op::BACKUP_MANAGE => host,
        // A Plane's rings are read under it, a key bundle's resource a Plane's (WP-3.4).
        op::KEYS_READ | op::AUDIT_READ | op::STREAMS_READ => host || plane(None),
        op::GC_MANAGE => plane(None),
        op::CATALOG_READ | op::CATALOG_WRITE | op::POLICY_PUSH | op::EVIDENCE_READ => {
            plane(Some("control"))
        }
        op::DECISION_EVALUATE | op::EVENT_SUBMIT => plane(Some("data")),
        _ => false,
    }
}

/// The longest principal, in bytes.
pub const MAX_PRINCIPAL_BYTES: usize = 512;

/// The reserved principal of a request that presented no credential: it holds only the grants
/// the configuration declares public, and no mapper rule may produce it.
pub const ANONYMOUS: &str = "anonymous";

/// The exact identifier grant lookup uses, byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Principal(String);

impl Principal {
    /// Accepts 1 to 512 bytes of UTF-8 without NUL or control characters, exactly as given: no
    /// trimming, folding or normalization, because the mapper already produced the exact form.
    pub fn new(identifier: impl Into<String>) -> Result<Self, ParseError> {
        let identifier = identifier.into();
        if identifier.is_empty() {
            return Err(ParseError::Principal("empty".to_owned()));
        }
        if identifier.len() > MAX_PRINCIPAL_BYTES {
            return Err(ParseError::Principal(format!(
                "{} bytes, over the {MAX_PRINCIPAL_BYTES} allowed",
                identifier.len()
            )));
        }
        if identifier.chars().any(char::is_control) {
            return Err(ParseError::Principal(
                "holds NUL or a control character".to_owned(),
            ));
        }
        Ok(Self(identifier))
    }

    /// The reserved anonymous principal.
    pub fn anonymous() -> Self {
        Self(ANONYMOUS.to_owned())
    }

    /// Whether this is the reserved anonymous principal.
    pub fn is_anonymous(&self) -> bool {
        self.0 == ANONYMOUS
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How an actor was authenticated, for the audit trail and the log, never for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Credential {
    /// An mTLS certificate whose fingerprint the bootstrap commitment names.
    Certificate,
    /// An access token the Authority Plane signed (`2-security/8`): what the actor may do is the
    /// token's scopes.
    AccessToken,
}

/// One scope an access token carries: operations on a selector (`2-security/8` Authorization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenScope {
    /// The operations, each a registered one.
    pub operations: std::collections::BTreeSet<String>,
    /// Where they apply.
    pub selector: Selector,
}

/// What an access token lets its bearer do (`2-security/8`): its scopes, and the status list it
/// was checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenGrant {
    /// The scopes the token carries, at most [`MAX_TOKEN_SCOPES`].
    pub scopes: Vec<TokenScope>,
    pub jti: String,
    /// The status list the token was found `VALID` in: its `uri`, `iat` and the SHA-256 of its
    /// bytes, what a decision record names (WP-12.5).
    pub list_uri: String,
    pub list_iat: u64,
    pub list_digest: [u8; 32],
}

/// The most scopes a service account holds, and a token carries.
pub const MAX_TOKEN_SCOPES: usize = 64;

/// The status list version an access token was found `VALID` in, as a decision or event record
/// names it (iteration 02, WP-12.5): never the token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenStatusRef {
    /// The list's `uri`, the token's `status.status_list.uri`.
    pub uri: String,
    /// The list token's `iat`.
    pub iat: u64,
    /// `sha256:` and the hex SHA-256 of the list token's bytes.
    pub digest: String,
}

impl TokenGrant {
    /// The status list version this token was checked against.
    pub fn status_ref(&self) -> TokenStatusRef {
        TokenStatusRef {
            uri: self.list_uri.clone(),
            iat: self.list_iat,
            digest: format!(
                "sha256:{}",
                self.list_digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
        }
    }
}

impl Actor {
    /// The status list version the actor's access token was checked against, when it acted by one.
    pub fn token_status(&self) -> Option<TokenStatusRef> {
        match self {
            Self::Authenticated(context) => context.token().map(TokenGrant::status_ref),
            _ => None,
        }
    }
}

/// Whether `operation` on `resource` is a per-Host operation on a Host's own resources: the Host
/// itself, or a Plane's resource for an operation that applies to one (its rings, audit, streams,
/// collection). What a Host's bootstrap principal reaches (`2-security/8`); never an evaluation,
/// an event, the catalog or the Authority Plane's accounts.
pub fn per_host_reach(operation: &str, resource: &Resource) -> bool {
    use operations as op;
    matches!(
        operation,
        op::IDENTITY_READ
            | op::IDENTITY_ADMIN
            | op::KEYS_READ
            | op::KEYS_ADMIN
            | op::MEMBERSHIP_READ
            | op::MEMBERSHIP_ADMIN
            | op::CONFIG_READ
            | op::LIFECYCLE_READ
            | op::BACKUP_READ
            | op::BACKUP_MANAGE
            | op::AUDIT_READ
            | op::STREAMS_READ
            | op::GC_MANAGE
    ) && match resource {
        Resource::Host => operation_fits(operation, &Selector::exactly(Resource::Host)),
        Resource::Plane { .. } | Resource::Zone { .. } | Resource::Ledger { .. } => {
            operation_fits(operation, &Selector::under(resource.clone()))
        }
    }
}

impl TokenGrant {
    /// Whether the token allows `operation` on `resource`: step 7 of `2-security/8` Verifying a
    /// token.
    pub fn permits(&self, operation: &str, resource: &Resource) -> bool {
        self.allows(operation, |selector| selector.contains(resource))
    }

    /// Whether the token allows `operation` on something at or under `scope`.
    pub fn permits_anywhere_under(&self, operation: &str, scope: &Resource) -> bool {
        self.allows(operation, |selector| {
            selector.contains(scope) || selector.reaches_under(scope)
        })
    }

    /// Whether the token allows `operation` on everything under `scope`, whole.
    pub fn permits_whole(&self, operation: &str, scope: &Resource) -> bool {
        self.allows(operation, |selector| selector.covers_whole(scope))
    }

    /// The operations the token carries, every scope together.
    pub fn operations(&self) -> std::collections::BTreeSet<&str> {
        self.scopes
            .iter()
            .flat_map(|scope| scope.operations.iter().map(String::as_str))
            .collect()
    }

    fn allows(&self, operation: &str, selected: impl Fn(&Selector) -> bool) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope.operations.contains(operation) && selected(&scope.selector))
    }
}

impl Credential {
    /// The credential kind as the trail spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::AccessToken => "access_token",
        }
    }
}

/// Who a request acts as, established once at the authentication boundary and immutable after.
///
/// The display label is what a log line shows; it never reaches grant lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorContext {
    principal: Principal,
    credential: Credential,
    display: Option<String>,
    /// The token's grant, when the actor is an access token's bearer (WP-12.2).
    token: Option<std::sync::Arc<TokenGrant>>,
}

impl ActorContext {
    /// An actor the mapper produced from `credential`, with `display` for the log.
    pub fn new(principal: Principal, credential: Credential, display: Option<String>) -> Self {
        Self {
            principal,
            credential,
            display,
            token: None,
        }
    }

    /// The bearer of an access token: its subject, acting within `grant` (WP-12.2).
    pub fn of_token(principal: Principal, grant: TokenGrant) -> Self {
        Self {
            principal,
            credential: Credential::AccessToken,
            display: None,
            token: Some(std::sync::Arc::new(grant)),
        }
    }

    /// The token's grant, when the actor bears one.
    pub fn token(&self) -> Option<&TokenGrant> {
        self.token.as_deref()
    }

    /// The identifier grant lookup uses, byte for byte.
    pub fn authorization_principal(&self) -> &Principal {
        &self.principal
    }

    /// How the actor was authenticated.
    pub fn credential(&self) -> Credential {
        self.credential
    }

    /// A label for a person; never an identifier.
    pub fn display(&self) -> Option<&str> {
        self.display.as_deref()
    }
}

/// What the transport established about a request's caller: an authenticated actor, nobody, or
/// a credential no rule maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    /// A credential a mapper rule accepted.
    Authenticated(ActorContext),
    /// No credential presented: the reserved `anonymous` principal, with the public grants only.
    Anonymous,
    /// A credential was presented and no rule maps it: unauthenticated, whatever the public
    /// grants say, so a stranger's certificate never widens to the public ones.
    Unmapped {
        /// Why, for the log: the credential's kind and what it carried.
        reason: String,
    },
}

impl Actor {
    /// The principal grant lookup uses, or the denial a lookup must answer with instead.
    pub fn principal(&self) -> Result<Principal, AccessDenial> {
        match self {
            Self::Authenticated(context) => Ok(context.authorization_principal().clone()),
            Self::Anonymous => Ok(Principal::anonymous()),
            Self::Unmapped { .. } => Err(AccessDenial::unauthenticated(
                "the credential presented is not one this deployment maps to a principal",
            )),
        }
    }

    /// The denial for an actor without a grant: 401 for nobody, 403 for somebody.
    pub fn without_grant(&self) -> AccessDenial {
        match self {
            Self::Authenticated(_) => AccessDenial::forbidden(
                "this principal holds no grant for the operation on this resource",
            ),
            Self::Anonymous => AccessDenial::unauthenticated(
                "this operation requires an authenticated principal with a grant",
            ),
            Self::Unmapped { .. } => AccessDenial::unauthenticated(
                "the credential presented is not one this deployment maps to a principal",
            ),
        }
    }

    /// A label for the log: the display name, the principal, or what went wrong.
    pub fn label(&self) -> String {
        match self {
            Self::Authenticated(context) => context.display().map_or_else(
                || context.authorization_principal().to_string(),
                str::to_owned,
            ),
            Self::Anonymous => ANONYMOUS.to_owned(),
            Self::Unmapped { reason } => format!("unmapped: {reason}"),
        }
    }
}

/// One active allow, as `authorize` reads it: a grant record's operations and types, unfolded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Allow {
    pub principal: Principal,
    pub operation: String,
    pub selector: Selector,
    pub resource_type: String,
}

impl Allow {
    /// Whether this allow lets `principal` do `operation` on `resource`.
    pub fn permits(&self, principal: &Principal, operation: &str, resource: &Resource) -> bool {
        &self.principal == principal
            && self.operation == operation
            && self.selector.contains(resource)
            && (self.resource_type == resource_types::ANY
                || self.resource_type == resource.resource_type())
    }
}

/// The active allows at one revision: what `authorize` decides from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowSet {
    allows: Vec<Allow>,
    revision: u64,
}

impl AllowSet {
    /// A set at `revision`.
    pub fn new(allows: Vec<Allow>, revision: u64) -> Self {
        Self { allows, revision }
    }

    /// The grant-store revision this set was built at.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Every allow.
    pub fn allows(&self) -> &[Allow] {
        &self.allows
    }

    /// Adds every allow of `other`.
    pub fn extend(&mut self, other: &AllowSet) {
        self.allows.extend(other.allows.iter().cloned());
    }

    /// Whether `principal` may do `operation` on `resource`: deny by default.
    pub fn permits(&self, principal: &Principal, operation: &str, resource: &Resource) -> bool {
        self.allows
            .iter()
            .any(|allow| allow.permits(principal, operation, resource))
    }

    /// Whether `principal` holds any allow for `operation` at or under `scope`: the first stage
    /// of a lookup that resolves a name, which must be refused before any lookup for a principal
    /// with nothing there.
    pub fn permits_anywhere_under(
        &self,
        principal: &Principal,
        operation: &str,
        scope: &Resource,
    ) -> bool {
        self.allows.iter().any(|allow| {
            &allow.principal == principal
                && allow.operation == operation
                && (allow.selector.contains(scope) || allow.selector.reaches_under(scope))
        })
    }

    /// Whether `principal` may do `operation` on everything under `scope`, so an unknown name
    /// there is honestly not found rather than indistinguishable from out of scope.
    pub fn permits_whole(&self, principal: &Principal, operation: &str, scope: &Resource) -> bool {
        self.allows.iter().any(|allow| {
            &allow.principal == principal
                && allow.operation == operation
                && allow.resource_type == resource_types::ANY
                && allow.selector.covers_whole(scope)
        })
    }
}

/// What establishes who a request acts as: the Host's credential mapper, behind the transport.
///
/// The transport asks it once per request, with what the connection authenticated and the bearer
/// token the request carried, and attaches the answer to the request; nothing after the boundary
/// can change it.
pub trait Authenticator: Send + Sync {
    /// Who the request acts as. Nothing presented is [`Actor::Anonymous`]; a credential no rule
    /// maps is [`Actor::Unmapped`]; a token that fails verification is a denial.
    fn authenticate(
        &self,
        peer: Option<&crate::PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<Actor, AccessDenial>;
}

/// Checks a URL a Host fetches from, the Authority Plane's: `https`, or `http` where plain HTTP is
/// allowed; a host; no credentials, no fragment. Answers why it is not one.
pub fn check_service_url(url: &str, allow_http: bool) -> Result<(), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("`{url}` is not an absolute URL"))?;
    match scheme {
        "https" => {}
        "http" if allow_http => {}
        "http" => {
            return Err(format!(
                "`{url}` is plain HTTP, accepted only under the `development` profile"
            ));
        }
        _ => return Err(format!("`{url}` is neither https nor http")),
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(format!("`{url}` names no host"));
    }
    if authority.contains('@') {
        return Err(format!("`{url}` carries credentials"));
    }
    if url.contains('#') {
        return Err(format!("`{url}` carries a fragment"));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("`{url}` carries whitespace"));
    }
    Ok(())
}

/// One `host.authz.public[]` entry: what anybody may do, declared and never journaled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicGrantRule {
    pub operations: Vec<String>,
    pub selector: Selector,
    pub resource_types: Vec<String>,
}

/// The `host` section's public grants, typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAuth {
    pub public: Vec<PublicGrantRule>,
}

/// The authenticator of a deployment with no rules: nothing presented is anonymous, anything
/// presented is unmapped. The default every surface decides with, so a composition that forgot
/// its mapper is closed to credentials, never open to them.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRules;

impl Authenticator for NoRules {
    fn authenticate(
        &self,
        peer: Option<&crate::PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<Actor, AccessDenial> {
        match (peer, bearer) {
            (None, None) => Ok(Actor::Anonymous),
            (Some(peer), _) => Ok(Actor::Unmapped {
                reason: format!(
                    "certificate sha256:{} presented to a deployment with no credential rule",
                    peer.fingerprint()
                ),
            }),
            (None, Some(_)) => Err(AccessDenial::unauthenticated(
                "this deployment accepts no bearer token",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// WP-11.6, `2-security/6` Grant coherence: each operation fits the selectors that contain a
    /// resource it applies to, and no other.
    #[test]
    fn a_grant_fits_only_where_its_operation_applies() {
        let fits = |operation: &str, selector: &str| {
            operation_fits(operation, &Selector::parse(selector).expect("a selector"))
        };
        for (operation, fitting, not) in [
            (
                operations::ACCOUNTS_WRITE,
                vec!["plane/authority", "plane/authority/*"],
                vec!["plane/data/*", "host"],
            ),
            (
                operations::IDENTITY_READ,
                vec!["host", "host/*"],
                vec!["plane/control/*", "plane/authority"],
            ),
            (
                operations::AUDIT_READ,
                vec![
                    "host",
                    "plane/data/*",
                    "plane/control/zone/z",
                    "plane/authority",
                ],
                vec![],
            ),
            (operations::GC_MANAGE, vec!["plane/control/*"], vec!["host"]),
            (
                operations::CATALOG_READ,
                vec!["plane/control/*", "plane/control/zone/billing/ledger/l"],
                vec!["plane/data/*", "host"],
            ),
            (
                operations::DECISION_EVALUATE,
                vec!["plane/data/*", "plane/data/zone/billing/*"],
                vec!["plane/control/*", "host/*", "plane/authority"],
            ),
        ] {
            for selector in fitting {
                assert!(fits(operation, selector), "{operation} on {selector}");
            }
            for selector in not {
                assert!(!fits(operation, selector), "{operation} on {selector}");
            }
        }
        assert!(!fits("nothing.registered", "host"));
    }

    /// WP-6.3c: the evidence reads' operation is registered, so a grant naming it is accepted at
    /// issue and loaded.
    #[test]
    fn evidence_read_is_a_registered_operation() {
        assert_eq!(operations::EVIDENCE_READ, "evidence.read");
        assert!(operations::is_registered(operations::EVIDENCE_READ));
        assert_eq!(
            operations::ALL
                .iter()
                .filter(|held| **held == operations::EVIDENCE_READ)
                .count(),
            1
        );
    }

    /// WP-7.8: the backup operations are registered, once each, as the command table names them.
    #[test]
    fn the_backup_operations_are_registered() {
        for (operation, name) in [
            (operations::BACKUP_MANAGE, "backup.manage"),
            (operations::BACKUP_READ, "backup.read"),
        ] {
            assert_eq!(operation, name);
            assert_eq!(
                operations::ALL
                    .iter()
                    .filter(|held| **held == operation)
                    .count(),
                1
            );
        }
    }

    fn principal(name: &str) -> Principal {
        Principal::new(name).expect("a principal")
    }

    fn allow(name: &str, operation: &str, selector: &str, resource_type: &str) -> Allow {
        Allow {
            principal: principal(name),
            operation: operation.to_owned(),
            selector: Selector::parse(selector).expect("a selector"),
            resource_type: resource_type.to_owned(),
        }
    }

    #[test]
    fn resources_read_and_print_in_the_four_shapes_and_nothing_else() {
        for text in [
            "host",
            "plane/control",
            "plane/control/zone/z1",
            "plane/data/zone/z1/ledger/l1",
        ] {
            assert_eq!(Resource::parse(text).expect("a resource").to_string(), text);
        }
        for text in [
            "",
            "plane",
            "plane/control/zone",
            "zone/z1",
            "plane/*/zone/z1",
            "plane/control/zone/z1/ledger",
            "plane/control/zone/z1/ledger/l1/ref/main",
            "plane/con trol",
            "host/",
        ] {
            assert!(Resource::parse(text).is_err(), "{text}");
        }
        assert_eq!(
            Resource::parse("plane/data/zone/z1/ledger/l1")
                .expect("a resource")
                .resource_type(),
            "ledger"
        );
    }

    #[test]
    fn a_selector_contains_its_prefix_and_its_descendants_only_when_it_says_so() {
        let exact = Selector::parse("plane/control/zone/z1").expect("a selector");
        let under = Selector::parse("plane/control/zone/z1/*").expect("a selector");
        let zone = Resource::zone("control", "z1");
        let ledger = Resource::ledger("control", "z1", "l1");
        let other = Resource::zone("control", "z10");
        assert!(exact.contains(&zone));
        assert!(!exact.contains(&ledger));
        assert!(under.contains(&zone));
        assert!(under.contains(&ledger));
        assert!(!under.contains(&other), "component-aligned, not textual");
        assert!(!under.contains(&Resource::zone("data", "z1")));
        assert_eq!(under.to_string(), "plane/control/zone/z1/*");
        assert!(Selector::parse("plane/control/zone/*").is_err(), "diagonal");
        assert!(Selector::parse("plane/control/*/*").is_err());
        assert!(
            !Selector::parse("host/*")
                .expect("a selector")
                .contains(&Resource::plane("data")),
            "nothing lies under the Host in the tree"
        );
    }

    #[test]
    fn a_principal_is_exact_bounded_and_free_of_control_characters() {
        assert_eq!(
            principal("spiffe://acme/billing").as_str(),
            "spiffe://acme/billing"
        );
        assert_eq!(principal(" padded ").as_str(), " padded ", "never trimmed");
        assert!(Principal::new("").is_err());
        assert!(Principal::new("a\u{0}b").is_err());
        assert!(Principal::new("a\nb").is_err());
        assert!(Principal::new("x".repeat(512)).is_ok());
        assert!(Principal::new("x".repeat(513)).is_err());
        assert!(
            Principal::new("é".repeat(256)).is_ok(),
            "512 bytes of UTF-8"
        );
        assert!(Principal::new("é".repeat(257)).is_err());
        assert!(Principal::anonymous().is_anonymous());
    }

    #[test]
    fn authorize_is_deny_by_default_and_matches_principal_operation_selector_and_type() {
        let set = AllowSet::new(
            vec![
                allow(
                    "billing",
                    "catalog.read",
                    "plane/control/zone/billing/*",
                    "*",
                ),
                allow("ops", "catalog.write", "plane/control", "plane"),
            ],
            7,
        );
        let billing = principal("billing");
        let people = Resource::zone("control", "people");
        let own = Resource::ledger("control", "billing", "main");
        assert!(set.permits(&billing, "catalog.read", &own));
        assert!(!set.permits(&billing, "catalog.read", &people), "F-22");
        assert!(
            !set.permits(&billing, "catalog.write", &own),
            "another operation"
        );
        assert!(!set.permits(&principal("people"), "catalog.read", &own));
        let ops = principal("ops");
        assert!(set.permits(&ops, "catalog.write", &Resource::plane("control")));
        assert!(
            !set.permits(&ops, "catalog.write", &people),
            "an exact selector does not descend"
        );
        assert!(
            !set.permits(&principal("anonymous"), "catalog.read", &own),
            "nothing granted is nothing allowed"
        );
        assert_eq!(set.revision(), 7);
    }

    #[test]
    fn the_two_stage_rule_reads_anywhere_under_and_whole() {
        let set = AllowSet::new(
            vec![
                allow(
                    "billing",
                    "catalog.read",
                    "plane/control/zone/billing/*",
                    "*",
                ),
                allow("auditor", "catalog.read", "plane/control/*", "*"),
                allow("typed", "catalog.read", "plane/control/*", "zone"),
            ],
            1,
        );
        let plane = Resource::plane("control");
        assert!(set.permits_anywhere_under(&principal("billing"), "catalog.read", &plane));
        assert!(!set.permits_anywhere_under(&principal("billing"), "catalog.write", &plane));
        assert!(!set.permits_anywhere_under(
            &principal("billing"),
            "catalog.read",
            &Resource::plane("data")
        ));
        assert!(!set.permits_whole(&principal("billing"), "catalog.read", &plane));
        assert!(set.permits_whole(&principal("auditor"), "catalog.read", &plane));
        assert!(
            !set.permits_whole(&principal("typed"), "catalog.read", &plane),
            "a typed allow does not cover every type"
        );
        assert!(set.permits_anywhere_under(
            &principal("auditor"),
            "catalog.read",
            &Resource::zone("control", "anything")
        ));
    }

    #[test]
    fn an_actor_answers_401_for_nobody_and_403_for_somebody() {
        let somebody = Actor::Authenticated(ActorContext::new(
            principal("cert:sha256:ab"),
            Credential::Certificate,
            Some("CN=billing".to_owned()),
        ));
        assert_eq!(somebody.without_grant().http_status(), 403);
        assert_eq!(Actor::Anonymous.without_grant().http_status(), 401);
        let unmapped = Actor::Unmapped {
            reason: "certificate sha256:ab".to_owned(),
        };
        assert_eq!(unmapped.without_grant().http_status(), 401);
        assert!(unmapped.principal().is_err(), "never a principal");
        assert_eq!(
            Actor::Anonymous.principal().expect("anonymous"),
            Principal::anonymous()
        );
        assert_eq!(somebody.label(), "CN=billing", "the display is for the log");
    }

    #[test]
    fn no_rules_is_anonymous_for_nobody_and_closed_to_every_credential() {
        let peer = crate::PeerIdentity::new("CN=x", None, "ab", "01");
        assert_eq!(
            NoRules.authenticate(None, None).expect("answers"),
            Actor::Anonymous
        );
        assert!(matches!(
            NoRules.authenticate(Some(&peer), None).expect("answers"),
            Actor::Unmapped { .. }
        ));
        assert!(NoRules.authenticate(None, Some("token")).is_err());
    }

    /// Step 7 of `2-security/8` Verifying a token: a token permits exactly what one of its scopes
    /// names, an operation on a resource its selector contains, and nothing else.
    #[test]
    fn a_token_permits_only_what_its_scopes_name() {
        let scope = |operations: &[&str], selector: &str| TokenScope {
            operations: operations.iter().map(|op| (*op).to_owned()).collect(),
            selector: Selector::parse(selector).expect("a selector"),
        };
        let grant = TokenGrant {
            scopes: vec![
                scope(
                    &[operations::DECISION_EVALUATE, operations::EVENT_SUBMIT],
                    "plane/data/zone/z/*",
                ),
                scope(&[operations::KEYS_READ, operations::BACKUP_MANAGE], "host"),
                scope(&[operations::ACCOUNTS_READ], "plane/authority"),
            ],
            jti: "j".to_owned(),
            list_uri: "u".to_owned(),
            list_iat: 1,
            list_digest: [0; 32],
        };
        let ledger = Resource::ledger("data", "z", "l");
        let other = Resource::ledger("data", "y", "l");
        let data = Resource::plane("data");

        assert!(grant.permits(operations::DECISION_EVALUATE, &ledger));
        assert!(grant.permits(operations::EVENT_SUBMIT, &ledger));
        assert!(
            !grant.permits(operations::DECISION_EVALUATE, &other),
            "another zone"
        );
        assert!(grant.permits_anywhere_under(operations::DECISION_EVALUATE, &data));
        assert!(
            !grant.permits_whole(operations::DECISION_EVALUATE, &data),
            "one zone only"
        );
        assert!(grant.permits(operations::KEYS_READ, &Resource::Host));
        assert!(grant.permits(operations::BACKUP_MANAGE, &Resource::Host));
        assert!(
            !grant.permits(operations::KEYS_READ, &data),
            "the scope is the Host alone"
        );
        assert!(grant.permits(operations::ACCOUNTS_READ, &Resource::plane("authority")));
        assert!(!grant.permits(operations::ACCOUNTS_WRITE, &Resource::plane("authority")));
        assert!(!grant.permits(operations::CATALOG_READ, &Resource::plane("control")));
        assert_eq!(
            grant.operations().len(),
            5,
            "every operation of every scope, once"
        );
    }

    /// `2-security/6` Scope coherence: the Authority Plane's operations fit `plane/authority`
    /// alone, and a per-Host operation reaches the Host's own resources, never an evaluation.
    #[test]
    fn the_authority_operations_fit_the_authority_plane_alone() {
        let authority = Selector::exactly(Resource::plane("authority"));
        for operation in [
            operations::ACCOUNTS_READ,
            operations::ACCOUNTS_WRITE,
            operations::TOKENS_READ,
            operations::TOKENS_REVOKE,
        ] {
            assert!(operation_fits(operation, &authority), "{operation}");
            assert!(!operation_fits(
                operation,
                &Selector::exactly(Resource::Host)
            ));
            assert!(!operation_fits(
                operation,
                &Selector::parse("plane/data/*").expect("a selector")
            ));
        }
        assert!(per_host_reach(operations::KEYS_READ, &Resource::Host));
        assert!(per_host_reach(
            operations::GC_MANAGE,
            &Resource::plane("data")
        ));
        assert!(!per_host_reach(
            operations::DECISION_EVALUATE,
            &Resource::plane("data")
        ));
        assert!(!per_host_reach(
            operations::ACCOUNTS_WRITE,
            &Resource::plane("authority")
        ));
    }
}
