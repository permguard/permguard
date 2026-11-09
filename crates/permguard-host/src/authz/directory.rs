// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's directory (WP-8.1): roles, their members, local users and the provider subjects
//! linked to them, and the service accounts with their credentials (iteration 02, WP-11.2), in a
//! journal of their own beside the grants (`1-architecture/1` Authorization
//! store, Local users and authentication methods).
//!
//! ```text
//! host/authz/directory/journal/     one frame per transition, kind 1, a DirectoryTransition
//! ```
//!
//! A transition is a closed CBOR map with integer labels (`contracts/cbor/directory.json`):
//!
//! | Label | Member            | Type              | In                                                           |
//! | ----- | ----------------- | ----------------- | ------------------------------------------------------------ |
//! | 1     | `kind`            | text              | every transition                                             |
//! | 2     | `revision`        | uint              | every transition: the directory revision it is               |
//! | 3     | `at`              | uint, seconds UTC | every transition                                             |
//! | 4     | `by`              | text              | every transition: who made it                                |
//! | 5     | `operation_id`    | bytes, 16         | optional: the security mutation that made it                 |
//! | 6     | `name`            | text              | every transition: the role, the user or the service account  |
//! | 7     | `description`     | text              | optional: `role.create`, `role.update`, `sa.*`               |
//! | 8     | `member`          | text              | `member.add`, `member.remove`                                |
//! | 9     | `email`           | text              | optional: `user.create`, `user.update`                       |
//! | 10    | `display`         | text              | optional: `user.create`, `user.update`                       |
//! | 11    | `password`        | text              | optional: `user.create`, `user.password`: a PHC string       |
//! | 12    | `factor`          | bytes             | optional: `user.factor`: the sealed secret; absent resets it |
//! | 13    | `status`          | text              | `user.status`, `sa.status`                                   |
//! | 14    | `subject`         | text              | `user.link`, `user.unlink`                                   |
//! | 15    | `owner`           | text              | optional: `sa.create`, `sa.update`                           |
//! | 16    | `credential_id`   | bytes, 16         | `credential.add`, `credential.revoke`                        |
//! | 17    | `credential_kind` | text              | `credential.add`                                             |
//! | 18    | `secret`          | text              | `credential.add` of a `client_secret`: a PHC string          |
//! | 19    | `public_key`      | bytes             | `credential.add` of a `private_key_jwt`                      |
//! | 20    | `algorithm`       | text              | `credential.add` of a `private_key_jwt`                      |
//! | 21    | `key_id`          | text              | `credential.add` of a `private_key_jwt`                      |
//! | 22    | `binding`         | text              | `credential.add` of a `tls_client_auth`                      |
//! | 23    | `expires_at`      | uint, seconds     | optional: `credential.add`                                   |
//!
//! The journal is the truth: it is replayed at every start, and what it holds is small. A
//! decision reads the directory at its revision; nothing here grants: a role acts through the
//! grants whose principal is `role:<name>`, which the grant store holds.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use permguard_core::authz::{ANONYMOUS, Principal};
use permguard_objects::cbor::{self, Value};

use super::record::{Labelled, RecordError, uint};
use crate::identity::record::uuid_text;
use crate::operations::journal::OperationId;
use crate::operations::mutation::Applying;
use crate::storage::StorageError;
use crate::storage::journal::{Journal, Options, Recovery};
use crate::storage::volume::Volume;

/// The directory's folder below `host/authz/`.
pub const DIRECTORY: &str = "directory";
/// Its journal's folder.
pub const JOURNAL: &str = "journal";
/// The one frame kind: a [`DirectoryTransition`].
pub const FRAME_TRANSITION: u16 = 1;
/// A transition larger than this is refused before it is parsed.
pub const MAX_TRANSITION_BYTES: usize = 16 * 1024;
/// The most roles a Host holds.
pub const MAX_ROLES: usize = 1_024;
/// The most members of one role.
pub const MAX_MEMBERS: usize = 10_000;
/// The most local users a Host holds.
pub const MAX_USERS: usize = 100_000;
/// The prefix of a role's principal.
pub const ROLE_PREFIX: &str = "role:";
/// The prefix of a local user's principal.
pub const USER_PREFIX: &str = "user:";
/// The prefix of a service account's principal.
pub const SERVICE_ACCOUNT_PREFIX: &str = "sa:";
/// The principal prefixes the Host mints itself, for its roles, local users, providers' subjects,
/// keys and service accounts: no certificate rule and no credential binding may name one, or it
/// would act as somebody the Host vouches for (WP-8.1, WP-11.2). Compared without case.
pub const RESERVED_PREFIXES: &[&str] = &["role:", "user:", "oidc:", "spki:", "sa:"];

/// Whether `principal` begins with a prefix the Host reserves, in any case.
pub fn is_reserved(principal: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|reserved| {
        principal
            .get(..reserved.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(reserved))
    })
}

/// The most service accounts a Host holds.
pub const MAX_SERVICE_ACCOUNTS: usize = 10_000;
/// The most live credentials of one service account: room for a rotation's overlap.
pub const MAX_LIVE_CREDENTIALS: usize = 8;
/// The most credentials, live or not, one service account keeps: revoked and expired ones stay
/// listed, and the oldest of them is dropped when a new one would pass this bound, so a rotation
/// never runs out of room.
pub const MAX_CREDENTIALS: usize = 256;

/// The kinds of transition.
pub mod kinds {
    pub const ROLE_CREATE: &str = "role.create";
    pub const ROLE_UPDATE: &str = "role.update";
    pub const ROLE_DELETE: &str = "role.delete";
    pub const MEMBER_ADD: &str = "member.add";
    pub const MEMBER_REMOVE: &str = "member.remove";
    pub const USER_CREATE: &str = "user.create";
    pub const USER_UPDATE: &str = "user.update";
    pub const USER_PASSWORD: &str = "user.password";
    pub const USER_FACTOR: &str = "user.factor";
    pub const USER_STATUS: &str = "user.status";
    pub const USER_LINK: &str = "user.link";
    pub const USER_UNLINK: &str = "user.unlink";
    pub const USER_DELETE: &str = "user.delete";
    pub const SA_CREATE: &str = "sa.create";
    pub const SA_UPDATE: &str = "sa.update";
    pub const SA_STATUS: &str = "sa.status";
    pub const SA_DELETE: &str = "sa.delete";
    pub const CREDENTIAL_ADD: &str = "credential.add";
    pub const CREDENTIAL_REVOKE: &str = "credential.revoke";
    /// Every kind, as the journal spells it.
    pub const ALL: &[&str] = &[
        ROLE_CREATE,
        ROLE_UPDATE,
        ROLE_DELETE,
        MEMBER_ADD,
        MEMBER_REMOVE,
        USER_CREATE,
        USER_UPDATE,
        USER_PASSWORD,
        USER_FACTOR,
        USER_STATUS,
        USER_LINK,
        USER_UNLINK,
        USER_DELETE,
        SA_CREATE,
        SA_UPDATE,
        SA_STATUS,
        SA_DELETE,
        CREDENTIAL_ADD,
        CREDENTIAL_REVOKE,
    ];
}

/// Whether `name` is a role name: 1 to 63 lowercase letters, digits, `-`, `_` or `.`.
pub fn is_role_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

/// Whether `name` is a user name: 1 to 128 lowercase letters, digits, `.`, `_`, `-`, `+` and
/// `@`, so an email address is one.
pub fn is_user_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'@')
        })
}

/// Whether `email` reads as one address: one `@`, something either side, no space, at most 254
/// bytes. The provider verifies addresses; this only keeps nonsense out of the directory.
pub fn is_email(email: &str) -> bool {
    let mut parts = email.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(local), Some(domain), None) if !local.is_empty() && domain.contains('.')
    ) && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// `role:<name>`.
pub fn role_principal(name: &str) -> String {
    format!("{ROLE_PREFIX}{name}")
}

/// A member's own role: `dp.<member_id>` (`2-security/8` Roles and elevation).
pub const MEMBER_ROLE_PREFIX: &str = "dp.";
/// The role that decides on every data plane.
pub const DATA_PLANES_ROLE: &str = "data-planes";

/// `dp.<member_id>`.
pub fn member_role(member_id: &str) -> String {
    format!("{MEMBER_ROLE_PREFIX}{member_id}")
}

/// Whether `name` is a member's role: `dp.` and a `member_id` in its canonical text, 8-4-4-4-12
/// lowercase hex. A role an operator named `dp.` and anything else is the operator's own.
pub fn is_member_role(name: &str) -> bool {
    name.strip_prefix(MEMBER_ROLE_PREFIX).is_some_and(|id| {
        id.len() == 36
            && id.bytes().enumerate().all(|(at, byte)| match at {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
            })
    })
}

/// Whether `name` is a role the IAM Host keeps itself: an operator assigns it, never makes,
/// describes or deletes it, and it is never a grant's principal.
pub fn is_system_role(name: &str) -> bool {
    name == DATA_PLANES_ROLE || is_member_role(name)
}

/// `user:<name>`.
pub fn user_principal(name: &str) -> String {
    format!("{USER_PREFIX}{name}")
}

/// `sa:<name>`.
pub fn service_account_principal(name: &str) -> String {
    format!("{SERVICE_ACCOUNT_PREFIX}{name}")
}

/// One directory transition, as the journal holds it.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectoryTransition {
    pub kind: String,
    pub revision: u64,
    pub at: u64,
    pub by: String,
    pub operation_id: Option<OperationId>,
    pub name: String,
    pub description: Option<String>,
    pub member: Option<String>,
    pub email: Option<String>,
    pub display: Option<String>,
    pub password: Option<String>,
    pub factor: Option<Vec<u8>>,
    pub status: Option<String>,
    pub subject: Option<String>,
    pub owner: Option<String>,
    pub credential_id: Option<[u8; 16]>,
    pub credential_kind: Option<String>,
    pub secret: Option<String>,
    pub public_key: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub key_id: Option<String>,
    pub binding: Option<String>,
    pub expires_at: Option<u64>,
    /// `role.create`, `role.update`: the longest a token elevated to the role lives, in seconds;
    /// `0` on an update clears it, absent leaves it.
    pub max_lifetime: Option<u64>,
}

/// Never a password, a factor or a client secret's hash: whether the transition holds one.
impl std::fmt::Debug for DirectoryTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = |value: bool| value.then_some("<set>");
        f.debug_struct("DirectoryTransition")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("at", &self.at)
            .field("by", &self.by)
            .field("operation_id", &self.operation_id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("member", &self.member)
            .field("email", &self.email)
            .field("display", &self.display)
            .field("password", &held(self.password.is_some()))
            .field("factor", &held(self.factor.is_some()))
            .field("status", &self.status)
            .field("subject", &self.subject)
            .field("owner", &self.owner)
            .field("credential_id", &self.credential_id)
            .field("credential_kind", &self.credential_kind)
            .field("secret", &held(self.secret.is_some()))
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("binding", &self.binding)
            .field("expires_at", &self.expires_at)
            .field("max_lifetime", &self.max_lifetime)
            .finish_non_exhaustive()
    }
}

impl DirectoryTransition {
    /// A transition of `kind` on `name`, with nothing else set.
    pub fn new(kind: &str, name: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            revision: 0,
            at: 0,
            by: String::new(),
            operation_id: None,
            name: name.to_owned(),
            description: None,
            member: None,
            email: None,
            display: None,
            password: None,
            factor: None,
            status: None,
            subject: None,
            owner: None,
            credential_id: None,
            credential_kind: None,
            secret: None,
            public_key: None,
            algorithm: None,
            key_id: None,
            binding: None,
            expires_at: None,
            max_lifetime: None,
        }
    }

    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.kind.clone())),
            (Value::Int(2), uint(self.revision)?),
            (Value::Int(3), uint(self.at)?),
            (Value::Int(4), Value::Text(self.by.clone())),
        ];
        if let Some(operation_id) = self.operation_id {
            pairs.push((
                Value::Int(5),
                Value::Bytes(operation_id.as_bytes().to_vec()),
            ));
        }
        pairs.push((Value::Int(6), Value::Text(self.name.clone())));
        let texts = [
            (7, &self.description),
            (8, &self.member),
            (9, &self.email),
            (10, &self.display),
            (11, &self.password),
        ];
        for (label, value) in texts {
            if let Some(value) = value {
                pairs.push((Value::Int(label), Value::Text(value.clone())));
            }
        }
        if let Some(factor) = &self.factor {
            pairs.push((Value::Int(12), Value::Bytes(factor.clone())));
        }
        if let Some(status) = &self.status {
            pairs.push((Value::Int(13), Value::Text(status.clone())));
        }
        if let Some(subject) = &self.subject {
            pairs.push((Value::Int(14), Value::Text(subject.clone())));
        }
        if let Some(owner) = &self.owner {
            pairs.push((Value::Int(15), Value::Text(owner.clone())));
        }
        if let Some(credential_id) = &self.credential_id {
            pairs.push((Value::Int(16), Value::Bytes(credential_id.to_vec())));
        }
        let texts = [(17, &self.credential_kind), (18, &self.secret)];
        for (label, value) in texts {
            if let Some(value) = value {
                pairs.push((Value::Int(label), Value::Text(value.clone())));
            }
        }
        if let Some(public_key) = &self.public_key {
            pairs.push((Value::Int(19), Value::Bytes(public_key.clone())));
        }
        let texts = [
            (20, &self.algorithm),
            (21, &self.key_id),
            (22, &self.binding),
        ];
        for (label, value) in texts {
            if let Some(value) = value {
                pairs.push((Value::Int(label), Value::Text(value.clone())));
            }
        }
        if let Some(expires_at) = self.expires_at {
            pairs.push((Value::Int(23), uint(expires_at)?));
        }
        if let Some(seconds) = self.max_lifetime {
            pairs.push((Value::Int(24), uint(seconds)?));
        }
        cbor::encode(&Value::Map(pairs)).map_err(|error| RecordError::Cbor(error.to_string()))
    }

    /// Reads the canonical bytes, refusing an unknown label, a missing required one, a value of
    /// another type, an unknown kind, or more than [`MAX_TRANSITION_BYTES`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_TRANSITION_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value =
            cbor::decode_canonical(bytes).map_err(|error| RecordError::Cbor(error.to_string()))?;
        let mut map = Labelled::new(value, 24)?;
        let transition = Self {
            kind: map.text(1)?,
            revision: map.uint(2)?,
            at: map.uint(3)?,
            by: map.text(4)?,
            operation_id: map.optional_operation_id(5)?,
            name: map.text(6)?,
            description: map.optional_text(7)?,
            member: map.optional_text(8)?,
            email: map.optional_text(9)?,
            display: map.optional_text(10)?,
            password: map.optional_text(11)?,
            factor: map.optional_bytes(12)?,
            status: map.optional_text(13)?,
            subject: map.optional_text(14)?,
            owner: map.optional_text(15)?,
            credential_id: map
                .optional_bytes(16)?
                .map(|bytes| {
                    <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| {
                        RecordError::Malformed("a credential id is 16 bytes".to_owned())
                    })
                })
                .transpose()?,
            credential_kind: map.optional_text(17)?,
            secret: map.optional_text(18)?,
            public_key: map.optional_bytes(19)?,
            algorithm: map.optional_text(20)?,
            key_id: map.optional_text(21)?,
            binding: map.optional_text(22)?,
            expires_at: map.optional_uint(23)?,
            max_lifetime: map.optional_uint(24)?,
        };
        map.finish()?;
        if !kinds::ALL.contains(&transition.kind.as_str()) {
            return Err(RecordError::Malformed(format!(
                "`{}` is not a directory transition",
                transition.kind
            )));
        }
        Ok(transition)
    }
}

/// A role, as the directory holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub members: BTreeSet<String>,
    /// The directory revision of its last transition.
    pub revision: u64,
    pub created_at: u64,
    pub created_by: String,
    /// The longest a token elevated to it lives, in seconds; none bounds it but its family.
    pub max_lifetime: Option<u64>,
}

/// The bounds of a role's `max_lifetime`, in seconds: a minute to a day.
pub const ROLE_MAX_LIFETIME: std::ops::RangeInclusive<u64> = 60..=86_400;

/// Whether a user may sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    Disabled,
}

impl UserStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// A local user, as the directory holds it. The password is a PHC string and the factor a
/// sealed secret: neither ever leaves the Host.
#[derive(Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub email: Option<String>,
    pub display: Option<String>,
    pub password: Option<String>,
    pub factor: Option<Vec<u8>>,
    pub status: UserStatus,
    pub links: BTreeSet<String>,
    pub revision: u64,
    pub created_at: u64,
    pub created_by: String,
    /// When the password was last set, which ends every session opened before.
    pub password_set_at: Option<u64>,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("email", &self.email)
            .field("status", &self.status)
            .field("password", &self.password.as_ref().map(|_| "<set>"))
            .field("factor", &self.factor.as_ref().map(|_| "<set>"))
            .field("links", &self.links)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl User {
    /// `user:<name>`.
    pub fn principal(&self) -> String {
        user_principal(&self.name)
    }
}

/// Whether a service account may obtain tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Suspended,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }
}

/// What a credential proves with, as the directory keeps it: never a secret, only its hash.
#[derive(Clone, PartialEq, Eq)]
pub enum CredentialMaterial {
    /// A `client_secret`: its Argon2id PHC string.
    Secret { phc: String },
    /// A `private_key_jwt`: the public key, its algorithm and its RFC 7638 `kid`.
    Key {
        algorithm: String,
        key: Vec<u8>,
        key_id: String,
    },
    /// A `tls_client_auth`: `spki:sha256:<hex>` or a SAN URI.
    Binding { binding: String },
}

impl CredentialMaterial {
    /// The kind, as the directory spells it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Secret { .. } => super::credentials::CLIENT_SECRET,
            Self::Key { .. } => super::credentials::PRIVATE_KEY_JWT,
            Self::Binding { .. } => super::credentials::TLS_CLIENT_AUTH,
        }
    }
}

impl std::fmt::Debug for CredentialMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret { .. } => f.write_str("Secret(<hash>)"),
            Self::Key {
                algorithm, key_id, ..
            } => write!(f, "Key({algorithm}, {key_id})"),
            Self::Binding { binding } => write!(f, "Binding({binding})"),
        }
    }
}

/// One credential of a service account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub id: [u8; 16],
    pub material: CredentialMaterial,
    /// The directory revision that made it.
    pub created_revision: u64,
    pub created_at: u64,
    pub created_by: String,
    pub expires_at: Option<u64>,
    /// When it was revoked; `None` while it is active.
    pub revoked_at: Option<u64>,
}

impl Credential {
    /// Whether it proves anything at `now`: not revoked, not expired.
    pub fn is_live_at(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expires| now < expires)
    }

    /// Its id, as a UUID.
    pub fn id_text(&self) -> String {
        uuid_text(&self.id)
    }
}

/// A service account, as the directory holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub name: String,
    pub owner: String,
    pub description: String,
    pub status: AccountStatus,
    pub credentials: Vec<Credential>,
    pub revision: u64,
    pub created_at: u64,
    pub created_by: String,
}

impl ServiceAccount {
    /// `sa:<name>`.
    pub fn principal(&self) -> String {
        service_account_principal(&self.name)
    }

    /// The credentials live at `now`.
    pub fn live_credentials(&self, now: u64) -> impl Iterator<Item = &Credential> {
        self.credentials
            .iter()
            .filter(move |credential| credential.is_live_at(now))
    }
}

/// Why the directory refused or failed a change.
#[derive(Debug)]
pub enum DirectoryError {
    Storage(StorageError),
    Record(RecordError),
    /// The revision the caller expected is not the directory's.
    Conflict {
        expected: u64,
        current: u64,
    },
    /// A request the directory never writes: a bad name, a bound passed, a link taken.
    Invalid(String),
    /// What it names does not exist.
    NotFound(String),
    /// What it creates exists already.
    Exists(String),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "the directory journal: {error}"),
            Self::Record(error) => write!(f, "a directory transition: {error}"),
            Self::Conflict { expected, current } => write!(
                f,
                "the directory is at revision {current}, not the {expected} the request expected"
            ),
            Self::Invalid(detail) | Self::NotFound(detail) | Self::Exists(detail) => {
                f.write_str(detail)
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

impl From<StorageError> for DirectoryError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<RecordError> for DirectoryError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// One change an operator or a sign-in asks of the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    CreateRole {
        name: String,
        description: String,
        /// The longest a token elevated to it lives; `None` or `0` for no bound but the family's.
        max_lifetime: Option<u64>,
    },
    UpdateRole {
        name: String,
        description: String,
        /// `None` leaves it, `0` clears it.
        max_lifetime: Option<u64>,
    },
    DeleteRole {
        name: String,
    },
    AddMember {
        role: String,
        member: String,
    },
    RemoveMember {
        role: String,
        member: String,
    },
    CreateUser {
        name: String,
        email: Option<String>,
        display: Option<String>,
        /// A PHC string, already hashed.
        password: Option<String>,
    },
    /// `None` leaves a field as it is; `Some("")` clears it.
    UpdateUser {
        name: String,
        email: Option<String>,
        display: Option<String>,
    },
    SetPassword {
        name: String,
        password: String,
    },
    /// `None` resets the factor.
    SetFactor {
        name: String,
        factor: Option<Vec<u8>>,
    },
    SetStatus {
        name: String,
        active: bool,
    },
    Link {
        name: String,
        subject: String,
    },
    Unlink {
        name: String,
        subject: String,
    },
    DeleteUser {
        name: String,
    },
    CreateServiceAccount {
        name: String,
        owner: String,
        description: String,
    },
    /// `None` leaves a field as it is.
    UpdateServiceAccount {
        name: String,
        owner: Option<String>,
        description: Option<String>,
    },
    SetAccountStatus {
        name: String,
        active: bool,
    },
    DeleteServiceAccount {
        name: String,
    },
    /// The material is already what the directory keeps: a secret arrives hashed.
    AddCredential {
        account: String,
        id: [u8; 16],
        material: CredentialMaterial,
        expires_at: Option<u64>,
    },
    RevokeCredential {
        account: String,
        id: [u8; 16],
    },
}

impl Change {
    /// What the change names: the role, the user or the service account.
    pub fn target(&self) -> &str {
        match self {
            Self::CreateRole { name, .. }
            | Self::UpdateRole { name, .. }
            | Self::DeleteRole { name }
            | Self::CreateUser { name, .. }
            | Self::UpdateUser { name, .. }
            | Self::SetPassword { name, .. }
            | Self::SetFactor { name, .. }
            | Self::SetStatus { name, .. }
            | Self::Link { name, .. }
            | Self::Unlink { name, .. }
            | Self::DeleteUser { name }
            | Self::CreateServiceAccount { name, .. }
            | Self::UpdateServiceAccount { name, .. }
            | Self::SetAccountStatus { name, .. }
            | Self::DeleteServiceAccount { name } => name,
            Self::AddMember { role, .. } | Self::RemoveMember { role, .. } => role,
            Self::AddCredential { account, .. } | Self::RevokeCredential { account, .. } => account,
        }
    }
}

/// What a change did: the revision after it, and whether it wrote anything. Adding a member
/// already there, or removing one absent, writes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    pub revision: u64,
    pub changed: bool,
}

#[derive(Debug, Default)]
struct State {
    revision: u64,
    roles: BTreeMap<String, Role>,
    users: BTreeMap<String, User>,
    /// Linked subject to user name.
    links: BTreeMap<String, String>,
    /// Lowercased email to user name.
    emails: BTreeMap<String, String>,
    accounts: BTreeMap<String, ServiceAccount>,
    /// An unrevoked `tls_client_auth` binding to its account: one binding names one account.
    bindings: BTreeMap<String, String>,
    /// The revision each operation produced and what it named.
    operations: BTreeMap<OperationId, (u64, String)>,
}

/// The Host's directory of one volume.
pub struct Directory {
    journal: Mutex<Journal>,
    state: RwLock<State>,
}

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

impl Directory {
    /// Opens the directory of `volume`, replaying its journal. A transition the replay cannot
    /// apply is corruption, never skipped.
    pub fn open(volume: &Volume) -> Result<(Arc<Self>, Recovery), DirectoryError> {
        let dir = volume
            .host()
            .subdir(super::store::DIRECTORY, true)?
            .subdir(DIRECTORY, true)?;
        let (journal, recovery) = Journal::open(
            dir.subdir(JOURNAL, true)?,
            volume.journal_options(Options::default()),
        )?;
        let mut state = State::default();
        for frame in journal.frames()? {
            if frame.kind != FRAME_TRANSITION {
                return Err(DirectoryError::Invalid(format!(
                    "the directory journal holds a frame of kind {}",
                    frame.kind
                )));
            }
            let transition = DirectoryTransition::decode(&frame.payload)?;
            replay(&mut state, &transition)?;
        }
        Ok((
            Arc::new(Self {
                journal: Mutex::new(journal),
                state: RwLock::new(state),
            }),
            recovery,
        ))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The directory revision: the number of transitions applied.
    pub fn revision(&self) -> u64 {
        self.read().revision
    }

    pub fn roles(&self) -> Vec<Role> {
        self.read().roles.values().cloned().collect()
    }

    pub fn role(&self, name: &str) -> Option<Role> {
        self.read().roles.get(name).cloned()
    }

    pub fn users(&self) -> Vec<User> {
        self.read().users.values().cloned().collect()
    }

    pub fn user(&self, name: &str) -> Option<User> {
        self.read().users.get(name).cloned()
    }

    /// The user whose email is `email`, compared without case.
    pub fn user_by_email(&self, email: &str) -> Option<User> {
        let state = self.read();
        state
            .emails
            .get(&email.to_ascii_lowercase())
            .and_then(|name| state.users.get(name))
            .cloned()
    }

    /// The user a provider subject is linked to.
    pub fn user_of_subject(&self, subject: &str) -> Option<User> {
        let state = self.read();
        state
            .links
            .get(subject)
            .and_then(|name| state.users.get(name))
            .cloned()
    }

    pub fn service_accounts(&self) -> Vec<ServiceAccount> {
        self.read().accounts.values().cloned().collect()
    }

    pub fn service_account(&self, name: &str) -> Option<ServiceAccount> {
        self.read().accounts.get(name).cloned()
    }

    /// The service account a `tls_client_auth` binding names.
    pub fn account_of_binding(&self, binding: &str) -> Option<ServiceAccount> {
        let state = self.read();
        state
            .bindings
            .get(binding)
            .and_then(|name| state.accounts.get(name))
            .cloned()
    }

    /// The roles `principal` is a member of.
    pub fn roles_of(&self, principal: &str) -> Vec<String> {
        self.read()
            .roles
            .values()
            .filter(|role| role.members.contains(principal))
            .map(|role| role.name.clone())
            .collect()
    }

    /// The role principals that act for `principal`: the roles it is a member of, and, for a
    /// provider subject, the roles its issuer principal is a member of.
    pub fn subjects(&self, principal: &str, issuer: Option<&str>) -> Vec<Principal> {
        self.read()
            .roles
            .values()
            .filter(|role| {
                role.members.contains(principal)
                    || issuer.is_some_and(|issuer| role.members.contains(issuer))
            })
            .filter_map(|role| Principal::new(role_principal(&role.name)).ok())
            .collect()
    }

    /// The revision `operation_id` produced and what it named, when the journal holds it.
    pub fn operation(&self, operation_id: &OperationId) -> Option<(u64, String)> {
        self.read().operations.get(operation_id).cloned()
    }

    /// Applies `change` inside the operation `applying` names, as `by`, at `now`: refused when
    /// `expected_revision` is not the directory's, or when the directory would never hold the
    /// result. A change that changes nothing writes nothing.
    pub fn apply(
        &self,
        applying: &Applying<'_>,
        change: Change,
        by: &str,
        now: u64,
        expected_revision: Option<u64>,
    ) -> Result<Written, DirectoryError> {
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(expected) = expected_revision
            && expected != state.revision
        {
            return Err(DirectoryError::Conflict {
                expected,
                current: state.revision,
            });
        }
        if state.operations.contains_key(&applying.operation_id()) {
            return Err(DirectoryError::Invalid(format!(
                "the operation {} already wrote the directory; one operation writes it once",
                applying.operation_id()
            )));
        }
        let Some(mut transition) = plan(&state, &change, now)? else {
            return Ok(Written {
                revision: state.revision,
                changed: false,
            });
        };
        transition.revision = state.revision + 1;
        transition.at = now;
        transition.by = by.to_owned();
        transition.operation_id = Some(applying.operation_id());
        let bytes = transition.encode()?;
        // Checked before the write: a transition the replay would refuse is never journaled.
        let mut next = State {
            revision: state.revision,
            roles: state.roles.clone(),
            users: state.users.clone(),
            links: state.links.clone(),
            emails: state.emails.clone(),
            accounts: state.accounts.clone(),
            bindings: state.bindings.clone(),
            operations: BTreeMap::new(),
        };
        replay(&mut next, &transition)?;
        journal.append(FRAME_TRANSITION, &bytes)?;
        replay(&mut state, &transition)?;
        Ok(Written {
            revision: state.revision,
            changed: true,
        })
    }
}

/// The transition `change` writes against `state`, `None` when it changes nothing, or why it is
/// refused.
fn plan(
    state: &State,
    change: &Change,
    now: u64,
) -> Result<Option<DirectoryTransition>, DirectoryError> {
    use kinds::*;
    let role = |name: &str| {
        state
            .roles
            .get(name)
            .ok_or_else(|| DirectoryError::NotFound(format!("there is no role `{name}`")))
    };
    let user = |name: &str| {
        state
            .users
            .get(name)
            .ok_or_else(|| DirectoryError::NotFound(format!("there is no user `{name}`")))
    };
    let account = |name: &str| {
        state.accounts.get(name).ok_or_else(|| {
            DirectoryError::NotFound(format!("there is no service account `{name}`"))
        })
    };
    let owner = |text: &str| -> Result<(), DirectoryError> {
        if text.trim().is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
            return invalid(
                "an owner is the accountable team: 1 to 256 bytes, on one line".to_owned(),
            );
        }
        Ok(())
    };
    let description = |text: &str| -> Result<(), DirectoryError> {
        if text.len() > 1_024 || text.chars().any(char::is_control) {
            return invalid("a description is at most 1,024 bytes, on one line".to_owned());
        }
        Ok(())
    };
    let email_free = |email: &str, owner: Option<&str>| -> Result<(), DirectoryError> {
        if !is_email(email) {
            return invalid(format!("`{email}` is not an email address"));
        }
        match state.emails.get(&email.to_ascii_lowercase()) {
            Some(holder) if Some(holder.as_str()) != owner => Err(DirectoryError::Exists(format!(
                "the email `{email}` is the user `{holder}`'s"
            ))),
            _ => Ok(()),
        }
    };
    let password = |phc: &str| -> Result<(), DirectoryError> {
        if !phc.starts_with("$argon2id$") || phc.len() > 512 {
            return invalid("a password is kept only as an Argon2id PHC string".to_owned());
        }
        Ok(())
    };
    let display = |text: &str| -> Result<(), DirectoryError> {
        if text.len() > 256 || text.chars().any(char::is_control) {
            return invalid("a display name is at most 256 bytes, on one line".to_owned());
        }
        Ok(())
    };
    let lifetime = |seconds: Option<u64>| -> Result<(), DirectoryError> {
        match seconds {
            Some(seconds) if seconds != 0 && !ROLE_MAX_LIFETIME.contains(&seconds) => {
                invalid(format!(
                    "a role's max_lifetime is {} to {} seconds, or 0 for none",
                    ROLE_MAX_LIFETIME.start(),
                    ROLE_MAX_LIFETIME.end()
                ))
            }
            _ => Ok(()),
        }
    };
    let transition = match change {
        Change::CreateRole {
            name,
            description: text,
            max_lifetime,
        } => {
            if !is_role_name(name) {
                return invalid(format!(
                    "`{name}` is not a role name: 1 to 63 lowercase letters, digits, `-`, `_` or `.`"
                ));
            }
            if state.roles.contains_key(name) {
                return Err(DirectoryError::Exists(format!("the role `{name}` exists")));
            }
            if state.roles.len() >= MAX_ROLES {
                return invalid(format!("a Host holds at most {MAX_ROLES} roles"));
            }
            description(text)?;
            lifetime(*max_lifetime)?;
            let mut transition = DirectoryTransition::new(ROLE_CREATE, name);
            transition.description = Some(text.clone());
            transition.max_lifetime = max_lifetime.filter(|seconds| *seconds > 0);
            transition
        }
        Change::UpdateRole {
            name,
            description: text,
            max_lifetime,
        } => {
            role(name)?;
            description(text)?;
            lifetime(*max_lifetime)?;
            let mut transition = DirectoryTransition::new(ROLE_UPDATE, name);
            transition.description = Some(text.clone());
            transition.max_lifetime = *max_lifetime;
            transition
        }
        Change::DeleteRole { name } => {
            role(name)?;
            DirectoryTransition::new(ROLE_DELETE, name)
        }
        Change::AddMember { role: name, member } => {
            let held = role(name)?;
            check_member(state, member)?;
            if held.members.contains(member) {
                return Ok(None);
            }
            if held.members.len() >= MAX_MEMBERS {
                return invalid(format!("a role has at most {MAX_MEMBERS} members"));
            }
            let mut transition = DirectoryTransition::new(MEMBER_ADD, name);
            transition.member = Some(member.clone());
            transition
        }
        Change::RemoveMember { role: name, member } => {
            if !role(name)?.members.contains(member) {
                return Ok(None);
            }
            let mut transition = DirectoryTransition::new(MEMBER_REMOVE, name);
            transition.member = Some(member.clone());
            transition
        }
        Change::CreateUser {
            name,
            email,
            display: shown,
            password: phc,
        } => {
            if !is_user_name(name) {
                return invalid(format!(
                    "`{name}` is not a user name: 1 to 128 lowercase letters, digits, `.`, `_`, `-`, `+` or `@`"
                ));
            }
            if state.users.contains_key(name) {
                return Err(DirectoryError::Exists(format!("the user `{name}` exists")));
            }
            if state.users.len() >= MAX_USERS {
                return invalid(format!("a Host holds at most {MAX_USERS} users"));
            }
            if let Some(email) = email {
                email_free(email, None)?;
            }
            if let Some(shown) = shown {
                display(shown)?;
            }
            if let Some(phc) = phc {
                password(phc)?;
            }
            let mut transition = DirectoryTransition::new(USER_CREATE, name);
            transition.email = email.clone();
            transition.display = shown.clone();
            transition.password = phc.clone();
            transition
        }
        Change::UpdateUser {
            name,
            email,
            display: shown,
        } => {
            user(name)?;
            if let Some(email) = email.as_deref().filter(|email| !email.is_empty()) {
                email_free(email, Some(name))?;
            }
            if let Some(shown) = shown {
                display(shown)?;
            }
            let mut transition = DirectoryTransition::new(USER_UPDATE, name);
            transition.email = email.clone();
            transition.display = shown.clone();
            transition
        }
        Change::SetPassword {
            name,
            password: phc,
        } => {
            user(name)?;
            password(phc)?;
            let mut transition = DirectoryTransition::new(USER_PASSWORD, name);
            transition.password = Some(phc.clone());
            transition
        }
        Change::SetFactor { name, factor } => {
            user(name)?;
            let mut transition = DirectoryTransition::new(USER_FACTOR, name);
            transition.factor = factor.clone();
            transition
        }
        Change::SetStatus { name, active } => {
            let status = if *active {
                UserStatus::Active
            } else {
                UserStatus::Disabled
            };
            if user(name)?.status == status {
                return Ok(None);
            }
            let mut transition = DirectoryTransition::new(USER_STATUS, name);
            transition.status = Some(status.as_str().to_owned());
            transition
        }
        Change::Link { name, subject } => {
            user(name)?;
            if !is_linkable_subject(subject) {
                return invalid(format!(
                    "`{subject}` is not a provider subject: `oidc:<issuer>#<subject>`"
                ));
            }
            match state.links.get(subject) {
                Some(holder) if holder == name => return Ok(None),
                Some(holder) => {
                    return Err(DirectoryError::Exists(format!(
                        "`{subject}` is linked to the user `{holder}`"
                    )));
                }
                None => {}
            }
            let mut transition = DirectoryTransition::new(USER_LINK, name);
            transition.subject = Some(subject.clone());
            transition
        }
        Change::Unlink { name, subject } => {
            if !user(name)?.links.contains(subject) {
                return Ok(None);
            }
            let mut transition = DirectoryTransition::new(USER_UNLINK, name);
            transition.subject = Some(subject.clone());
            transition
        }
        Change::DeleteUser { name } => {
            user(name)?;
            DirectoryTransition::new(USER_DELETE, name)
        }
        Change::CreateServiceAccount {
            name,
            owner: team,
            description: text,
        } => {
            if !is_role_name(name) {
                return invalid(format!(
                    "`{name}` is not a service account name: 1 to 63 lowercase letters, digits, `-`, `_` or `.`"
                ));
            }
            if state.accounts.contains_key(name) {
                return Err(DirectoryError::Exists(format!(
                    "the service account `{name}` exists"
                )));
            }
            if state.accounts.len() >= MAX_SERVICE_ACCOUNTS {
                return invalid(format!(
                    "a Host holds at most {MAX_SERVICE_ACCOUNTS} service accounts"
                ));
            }
            owner(team)?;
            description(text)?;
            let mut transition = DirectoryTransition::new(SA_CREATE, name);
            transition.owner = Some(team.clone());
            transition.description = Some(text.clone());
            transition
        }
        Change::UpdateServiceAccount {
            name,
            owner: team,
            description: text,
        } => {
            let held = account(name)?;
            if let Some(team) = team {
                owner(team)?;
            }
            if let Some(text) = text {
                description(text)?;
            }
            if team.as_ref().is_none_or(|team| *team == held.owner)
                && text.as_ref().is_none_or(|text| *text == held.description)
            {
                return Ok(None);
            }
            let mut transition = DirectoryTransition::new(SA_UPDATE, name);
            transition.owner = team.clone();
            transition.description = text.clone();
            transition
        }
        Change::SetAccountStatus { name, active } => {
            let status = if *active {
                AccountStatus::Active
            } else {
                AccountStatus::Suspended
            };
            if account(name)?.status == status {
                return Ok(None);
            }
            let mut transition = DirectoryTransition::new(SA_STATUS, name);
            transition.status = Some(status.as_str().to_owned());
            transition
        }
        Change::DeleteServiceAccount { name } => {
            account(name)?;
            DirectoryTransition::new(SA_DELETE, name)
        }
        Change::AddCredential {
            account: name,
            id,
            material,
            expires_at,
        } => {
            let held = account(name)?;
            if held
                .credentials
                .iter()
                .any(|credential| credential.id == *id)
            {
                return Err(DirectoryError::Exists(format!(
                    "the credential {} exists",
                    uuid_text(id)
                )));
            }
            if held.live_credentials(now).count() >= MAX_LIVE_CREDENTIALS {
                return invalid(format!(
                    "the service account `{name}` holds {MAX_LIVE_CREDENTIALS} live credentials: revoke one first"
                ));
            }
            if let Some(expires_at) = expires_at
                && *expires_at <= now
            {
                return invalid("a credential's expiry is in the future".to_owned());
            }
            let mut transition = DirectoryTransition::new(CREDENTIAL_ADD, name);
            transition.credential_id = Some(*id);
            transition.credential_kind = Some(material.kind().to_owned());
            transition.expires_at = *expires_at;
            match material {
                CredentialMaterial::Secret { phc } => {
                    if !phc.starts_with("$argon2id$") || phc.len() > 512 {
                        return invalid(
                            "a client secret is kept only as an Argon2id PHC string".to_owned(),
                        );
                    }
                    transition.secret = Some(phc.clone());
                }
                CredentialMaterial::Key {
                    algorithm,
                    key,
                    key_id,
                } => {
                    // The kid is the key's thumbprint, recomputed here: never the caller's word.
                    if super::credentials::thumbprint(algorithm, key).as_ref() != Some(key_id) {
                        return invalid(format!(
                            "not an {algorithm} public key with the thumbprint `{key_id}`"
                        ));
                    }
                    if algorithm == super::credentials::EDDSA
                        && super::credentials::has_small_order(key)
                    {
                        return invalid("an Ed25519 key of small order is never kept".to_owned());
                    }
                    if held.credentials.iter().any(|credential| {
                        matches!(&credential.material, CredentialMaterial::Key { key_id: held, .. } if held == key_id)
                    }) {
                        return Err(DirectoryError::Exists(format!(
                            "the service account `{name}` holds the key `{key_id}` already"
                        )));
                    }
                    transition.public_key = Some(key.clone());
                    transition.algorithm = Some(algorithm.clone());
                    transition.key_id = Some(key_id.clone());
                }
                CredentialMaterial::Binding { binding } => {
                    super::credentials::binding(binding).map_err(DirectoryError::Invalid)?;
                    if let Some(holder) = state.bindings.get(binding) {
                        return Err(DirectoryError::Exists(format!(
                            "`{binding}` is bound to the service account `{holder}`"
                        )));
                    }
                    transition.binding = Some(binding.clone());
                }
            }
            transition
        }
        Change::RevokeCredential { account: name, id } => {
            let held = account(name)?;
            let credential = held
                .credentials
                .iter()
                .find(|credential| credential.id == *id)
                .ok_or_else(|| {
                    DirectoryError::NotFound(format!(
                        "the service account `{name}` has no credential {}",
                        uuid_text(id)
                    ))
                })?;
            if credential.revoked_at.is_some() {
                return Ok(None);
            }
            let mut transition = DirectoryTransition::new(CREDENTIAL_REVOKE, name);
            transition.credential_id = Some(*id);
            transition
        }
    };
    Ok(Some(transition))
}

fn invalid<T>(detail: String) -> Result<T, DirectoryError> {
    Err(DirectoryError::Invalid(detail))
}

/// Whether `subject` is a provider subject a user may be linked to: `oidc:<issuer>#<value>`.
pub fn is_linkable_subject(subject: &str) -> bool {
    subject
        .strip_prefix("oidc:")
        .and_then(|rest| rest.split_once('#'))
        .is_some_and(|(issuer, value)| !issuer.is_empty() && !value.is_empty())
        && Principal::new(subject).is_ok()
}

/// A member is a principal as the mapper produces it, or an issuer principal; never the reserved
/// `anonymous`, never a role; a local user or a service account that exists.
fn check_member(state: &State, member: &str) -> Result<(), DirectoryError> {
    if member == ANONYMOUS || member.starts_with(ROLE_PREFIX) {
        return Err(DirectoryError::Invalid(format!(
            "`{member}` cannot be a member: a member is a user, a service account, a certificate or a provider subject"
        )));
    }
    Principal::new(member)
        .map_err(|error| DirectoryError::Invalid(format!("`{member}`: {error}")))?;
    if let Some(name) = member.strip_prefix(USER_PREFIX)
        && !state.users.contains_key(name)
    {
        return Err(DirectoryError::NotFound(format!(
            "there is no user `{name}`"
        )));
    }
    if let Some(name) = member.strip_prefix(SERVICE_ACCOUNT_PREFIX)
        && !state.accounts.contains_key(name)
    {
        return Err(DirectoryError::NotFound(format!(
            "there is no service account `{name}`"
        )));
    }
    Ok(())
}

/// Applies one journaled transition to `state`: at start, and on a copy before every write. A
/// transition out of order, or naming what is not there, is corruption.
fn replay(state: &mut State, transition: &DirectoryTransition) -> Result<(), DirectoryError> {
    use kinds::*;
    let at = transition.revision;
    let corrupt = |detail: String| {
        DirectoryError::Invalid(format!("the directory journal at revision {at}: {detail}"))
    };
    if at != state.revision + 1 {
        return Err(corrupt(format!("it follows revision {}", state.revision)));
    }
    let name = transition.name.clone();
    let missing = |what: &str| corrupt(format!("{what} `{name}` does not exist"));
    match transition.kind.as_str() {
        ROLE_CREATE => {
            if state.roles.contains_key(&name) {
                return Err(corrupt(format!("the role `{name}` exists")));
            }
            state.roles.insert(
                name.clone(),
                Role {
                    name: name.clone(),
                    description: transition.description.clone().unwrap_or_default(),
                    members: BTreeSet::new(),
                    revision: at,
                    created_at: transition.at,
                    created_by: transition.by.clone(),
                    max_lifetime: transition.max_lifetime.filter(|seconds| *seconds > 0),
                },
            );
        }
        ROLE_UPDATE => {
            let role = state
                .roles
                .get_mut(&name)
                .ok_or_else(|| missing("the role"))?;
            role.description = transition.description.clone().unwrap_or_default();
            if let Some(seconds) = transition.max_lifetime {
                role.max_lifetime = (seconds > 0).then_some(seconds);
            }
            role.revision = at;
        }
        ROLE_DELETE => {
            state
                .roles
                .remove(&name)
                .ok_or_else(|| missing("the role"))?;
        }
        MEMBER_ADD | MEMBER_REMOVE => {
            let member = transition
                .member
                .clone()
                .ok_or_else(|| corrupt("a membership names no member".to_owned()))?;
            let role = state
                .roles
                .get_mut(&name)
                .ok_or_else(|| missing("the role"))?;
            if transition.kind == MEMBER_ADD {
                role.members.insert(member);
            } else {
                role.members.remove(&member);
            }
            role.revision = at;
        }
        USER_CREATE => {
            if state.users.contains_key(&name) {
                return Err(corrupt(format!("the user `{name}` exists")));
            }
            if let Some(email) = &transition.email {
                state
                    .emails
                    .insert(email.to_ascii_lowercase(), name.clone());
            }
            state.users.insert(
                name.clone(),
                User {
                    name: name.clone(),
                    email: transition.email.clone(),
                    display: transition.display.clone(),
                    password: transition.password.clone(),
                    factor: None,
                    status: UserStatus::Active,
                    links: BTreeSet::new(),
                    revision: at,
                    created_at: transition.at,
                    created_by: transition.by.clone(),
                    password_set_at: transition.password.as_ref().map(|_| transition.at),
                },
            );
        }
        USER_UPDATE => {
            let user = state
                .users
                .get_mut(&name)
                .ok_or_else(|| missing("the user"))?;
            if let Some(email) = &transition.email {
                if let Some(old) = user.email.take() {
                    state.emails.remove(&old.to_ascii_lowercase());
                }
                if !email.is_empty() {
                    state
                        .emails
                        .insert(email.to_ascii_lowercase(), name.clone());
                    user.email = Some(email.clone());
                }
            }
            if let Some(shown) = &transition.display {
                user.display = (!shown.is_empty()).then(|| shown.clone());
            }
            user.revision = at;
        }
        USER_PASSWORD => {
            let user = state
                .users
                .get_mut(&name)
                .ok_or_else(|| missing("the user"))?;
            user.password =
                Some(transition.password.clone().ok_or_else(|| {
                    corrupt("a password transition holds no password".to_owned())
                })?);
            user.password_set_at = Some(transition.at);
            user.revision = at;
        }
        USER_FACTOR => {
            let user = state
                .users
                .get_mut(&name)
                .ok_or_else(|| missing("the user"))?;
            user.factor = transition.factor.clone();
            user.revision = at;
        }
        USER_STATUS => {
            let status = transition
                .status
                .as_deref()
                .and_then(UserStatus::parse)
                .ok_or_else(|| corrupt("a status transition names no status".to_owned()))?;
            let user = state
                .users
                .get_mut(&name)
                .ok_or_else(|| missing("the user"))?;
            user.status = status;
            user.revision = at;
        }
        USER_LINK | USER_UNLINK => {
            let subject = transition
                .subject
                .clone()
                .ok_or_else(|| corrupt("a link names no subject".to_owned()))?;
            let user = state
                .users
                .get_mut(&name)
                .ok_or_else(|| missing("the user"))?;
            if transition.kind == USER_LINK {
                user.links.insert(subject.clone());
                state.links.insert(subject, name.clone());
            } else {
                user.links.remove(&subject);
                state.links.remove(&subject);
            }
            user.revision = at;
        }
        USER_DELETE => {
            let user = state
                .users
                .remove(&name)
                .ok_or_else(|| missing("the user"))?;
            for subject in &user.links {
                state.links.remove(subject);
            }
            if let Some(email) = &user.email {
                state.emails.remove(&email.to_ascii_lowercase());
            }
            let principal = user.principal();
            for role in state.roles.values_mut() {
                if role.members.remove(&principal) {
                    role.revision = at;
                }
            }
        }
        SA_CREATE => {
            if state.accounts.contains_key(&name) {
                return Err(corrupt(format!("the service account `{name}` exists")));
            }
            state.accounts.insert(
                name.clone(),
                ServiceAccount {
                    name: name.clone(),
                    owner: transition
                        .owner
                        .clone()
                        .ok_or_else(|| corrupt("a service account names no owner".to_owned()))?,
                    description: transition.description.clone().unwrap_or_default(),
                    status: AccountStatus::Active,
                    credentials: Vec::new(),
                    revision: at,
                    created_at: transition.at,
                    created_by: transition.by.clone(),
                },
            );
        }
        SA_UPDATE => {
            let account = state
                .accounts
                .get_mut(&name)
                .ok_or_else(|| missing("the service account"))?;
            if let Some(owner) = &transition.owner {
                account.owner = owner.clone();
            }
            if let Some(description) = &transition.description {
                account.description = description.clone();
            }
            account.revision = at;
        }
        SA_STATUS => {
            let status = transition
                .status
                .as_deref()
                .and_then(AccountStatus::parse)
                .ok_or_else(|| corrupt("a status transition names no status".to_owned()))?;
            let account = state
                .accounts
                .get_mut(&name)
                .ok_or_else(|| missing("the service account"))?;
            account.status = status;
            account.revision = at;
        }
        SA_DELETE => {
            let account = state
                .accounts
                .remove(&name)
                .ok_or_else(|| missing("the service account"))?;
            state.bindings.retain(|_, holder| *holder != name);
            let principal = account.principal();
            for role in state.roles.values_mut() {
                if role.members.remove(&principal) {
                    role.revision = at;
                }
            }
        }
        CREDENTIAL_ADD => {
            let id = transition
                .credential_id
                .ok_or_else(|| corrupt("a credential names no id".to_owned()))?;
            let material = match transition.credential_kind.as_deref() {
                Some(super::credentials::CLIENT_SECRET) => CredentialMaterial::Secret {
                    phc: transition
                        .secret
                        .clone()
                        .ok_or_else(|| corrupt("a client secret holds no hash".to_owned()))?,
                },
                Some(super::credentials::PRIVATE_KEY_JWT) => CredentialMaterial::Key {
                    algorithm: transition
                        .algorithm
                        .clone()
                        .ok_or_else(|| corrupt("a key names no algorithm".to_owned()))?,
                    key: transition
                        .public_key
                        .clone()
                        .ok_or_else(|| corrupt("a key credential holds no key".to_owned()))?,
                    key_id: transition
                        .key_id
                        .clone()
                        .ok_or_else(|| corrupt("a key names no id".to_owned()))?,
                },
                Some(super::credentials::TLS_CLIENT_AUTH) => CredentialMaterial::Binding {
                    binding: transition.binding.clone().ok_or_else(|| {
                        corrupt("a certificate credential holds no binding".to_owned())
                    })?,
                },
                _ => return Err(corrupt("a credential of no known kind".to_owned())),
            };
            let account = state
                .accounts
                .get_mut(&name)
                .ok_or_else(|| missing("the service account"))?;
            if account
                .credentials
                .iter()
                .any(|credential| credential.id == id)
            {
                return Err(corrupt(format!("the credential {} exists", uuid_text(&id))));
            }
            if let CredentialMaterial::Binding { binding } = &material {
                if state.bindings.contains_key(binding) {
                    return Err(corrupt(format!("`{binding}` is bound already")));
                }
                state.bindings.insert(binding.clone(), name.clone());
            }
            // The oldest credentials that prove nothing at this transition make room: at most
            // MAX_LIVE_CREDENTIALS are live, so there is always one to drop.
            while account.credentials.len() >= MAX_CREDENTIALS {
                let Some(oldest) = account
                    .credentials
                    .iter()
                    .position(|credential| !credential.is_live_at(transition.at))
                else {
                    return Err(corrupt(format!(
                        "the service account `{name}` holds {MAX_CREDENTIALS} live credentials"
                    )));
                };
                let dropped = account.credentials.remove(oldest);
                if let CredentialMaterial::Binding { binding } = &dropped.material
                    && state.bindings.get(binding) == Some(&name)
                {
                    state.bindings.remove(binding);
                }
            }
            account.credentials.push(Credential {
                id,
                material,
                created_revision: at,
                created_at: transition.at,
                created_by: transition.by.clone(),
                expires_at: transition.expires_at,
                revoked_at: None,
            });
            account.revision = at;
        }
        CREDENTIAL_REVOKE => {
            let id = transition
                .credential_id
                .ok_or_else(|| corrupt("a revocation names no credential".to_owned()))?;
            let account = state
                .accounts
                .get_mut(&name)
                .ok_or_else(|| missing("the service account"))?;
            let credential = account
                .credentials
                .iter_mut()
                .find(|credential| credential.id == id)
                .ok_or_else(|| {
                    corrupt(format!("the credential {} does not exist", uuid_text(&id)))
                })?;
            credential.revoked_at = Some(transition.at);
            if let CredentialMaterial::Binding { binding } = &credential.material {
                state.bindings.remove(binding);
            }
            account.revision = at;
        }
        other => return Err(corrupt(format!("`{other}` is not a directory transition"))),
    }
    state.revision = at;
    if let Some(operation_id) = transition.operation_id {
        state.operations.insert(operation_id, (at, name));
    }
    Ok(())
}

/// The domain name directory intents carry.
pub const MUTATION_DOMAIN: &str = "directory";

/// The directory, as recovery of the mutation journal sees it.
pub struct Recovering<'a>(pub &'a Directory);

impl crate::operations::mutation::Domain for Recovering<'_> {
    fn name(&self) -> &'static str {
        MUTATION_DOMAIN
    }

    fn observe(
        &self,
        operation_id: &OperationId,
        _target: Option<&str>,
    ) -> Option<crate::operations::mutation::Observed> {
        self.0.operation(operation_id).map(|(revision, target)| {
            crate::operations::mutation::Observed {
                revision,
                target: Some(target),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::assurance::AssuranceProfile;

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA";

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-authz-directory-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn open(root: &std::path::Path) -> Arc<Directory> {
        let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
        Directory::open(&volume).expect("opens").0
    }

    fn apply(directory: &Directory, op: u8, change: Change) -> Result<Written, DirectoryError> {
        directory.apply(
            &Applying::for_tests(op),
            change,
            "admin",
            1_800_000_000,
            None,
        )
    }

    fn user(name: &str, email: Option<&str>) -> Change {
        Change::CreateUser {
            name: name.to_owned(),
            email: email.map(str::to_owned),
            display: None,
            password: Some(PHC.to_owned()),
        }
    }

    /// `2-security/8` Roles and elevation: a role's bound on its tokens' lifetime is a minute to a
    /// day; an update without one leaves it, `0` clears it, and it survives a reopen.
    #[test]
    fn a_role_bounds_its_tokens_lifetime_and_keeps_the_bound_across_a_reopen() {
        let root = scratch("role-lifetime");
        let lifetime_of = |directory: &Directory| {
            directory
                .role("deciders")
                .and_then(|role| role.max_lifetime)
        };
        let update = |seconds: Option<u64>| Change::UpdateRole {
            name: "deciders".to_owned(),
            description: "decide".to_owned(),
            max_lifetime: seconds,
        };
        {
            let directory = open(&root);
            for refused in [30, 59, 86_401] {
                let error = apply(
                    &directory,
                    1,
                    Change::CreateRole {
                        name: "deciders".to_owned(),
                        description: String::new(),
                        max_lifetime: Some(refused),
                    },
                )
                .expect_err("out of bounds");
                assert!(error.to_string().contains("max_lifetime"), "{error}");
            }
            apply(
                &directory,
                2,
                Change::CreateRole {
                    name: "deciders".to_owned(),
                    description: String::new(),
                    max_lifetime: Some(900),
                },
            )
            .expect("a bounded role");
            assert_eq!(lifetime_of(&directory), Some(900));
            apply(&directory, 3, update(None)).expect("described");
            assert_eq!(
                lifetime_of(&directory),
                Some(900),
                "an update without one leaves it"
            );
            apply(&directory, 4, update(Some(600))).expect("narrowed");
            assert_eq!(lifetime_of(&directory), Some(600));
        }
        let directory = open(&root);
        assert_eq!(lifetime_of(&directory), Some(600), "kept across a reopen");
        apply(&directory, 5, update(Some(0))).expect("cleared");
        assert_eq!(lifetime_of(&directory), None);
        let directory = open(&root);
        assert_eq!(lifetime_of(&directory), None, "cleared across a reopen");
    }

    #[test]
    fn roles_members_users_and_links_survive_a_reopen() {
        let root = scratch("reopen");
        {
            let directory = open(&root);
            apply(
                &directory,
                1,
                Change::CreateRole {
                    name: "operators".to_owned(),
                    description: "who runs it".to_owned(),
                    max_lifetime: None,
                },
            )
            .expect("a role");
            apply(
                &directory,
                2,
                user("paperino", Some("Paperino@Hotmail.com")),
            )
            .expect("a user");
            apply(
                &directory,
                3,
                Change::AddMember {
                    role: "operators".to_owned(),
                    member: "user:paperino".to_owned(),
                },
            )
            .expect("a member");
            apply(
                &directory,
                4,
                Change::AddMember {
                    role: "operators".to_owned(),
                    member: "oidc:https://login.example".to_owned(),
                },
            )
            .expect("an issuer member");
            apply(
                &directory,
                5,
                Change::Link {
                    name: "paperino".to_owned(),
                    subject: "oidc:https://login.example#0042".to_owned(),
                },
            )
            .expect("a link");
            assert_eq!(directory.revision(), 5);
        }
        let directory = open(&root);
        assert_eq!(directory.revision(), 5);
        let role = directory.role("operators").expect("the role");
        assert_eq!(role.members.len(), 2);
        assert_eq!(role.description, "who runs it");
        let user = directory
            .user_by_email("paperino@hotmail.com")
            .expect("found without case");
        assert_eq!(user.name, "paperino");
        assert!(user.password_set_at.is_some());
        assert_eq!(
            directory
                .user_of_subject("oidc:https://login.example#0042")
                .expect("linked")
                .name,
            "paperino"
        );
        assert_eq!(directory.roles_of("user:paperino"), vec!["operators"]);
        let subjects: Vec<String> = directory
            .subjects(
                "oidc:https://login.example#somebody",
                Some("oidc:https://login.example"),
            )
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            subjects,
            vec!["role:operators"],
            "the issuer member stands for every subject"
        );
        assert!(
            directory
                .subjects(
                    "oidc:https://other.example#x",
                    Some("oidc:https://other.example")
                )
                .is_empty()
        );
        assert_eq!(
            directory.operation(&OperationId::from_bytes([5; 16])),
            Some((5, "paperino".to_owned()))
        );
    }

    #[test]
    fn deleting_a_user_removes_its_links_email_and_memberships_and_a_name_can_return() {
        let root = scratch("delete");
        let directory = open(&root);
        apply(
            &directory,
            1,
            Change::CreateRole {
                name: "readers".to_owned(),
                description: String::new(),
                max_lifetime: None,
            },
        )
        .expect("a role");
        apply(&directory, 2, user("alice", Some("alice@acme.com"))).expect("a user");
        apply(
            &directory,
            3,
            Change::AddMember {
                role: "readers".to_owned(),
                member: "user:alice".to_owned(),
            },
        )
        .expect("a member");
        apply(
            &directory,
            4,
            Change::Link {
                name: "alice".to_owned(),
                subject: "oidc:https://idp#a".to_owned(),
            },
        )
        .expect("a link");
        apply(
            &directory,
            5,
            Change::DeleteUser {
                name: "alice".to_owned(),
            },
        )
        .expect("deleted");
        assert!(directory.user("alice").is_none());
        assert!(directory.user_by_email("alice@acme.com").is_none());
        assert!(directory.user_of_subject("oidc:https://idp#a").is_none());
        assert!(
            directory
                .role("readers")
                .expect("the role")
                .members
                .is_empty()
        );
        apply(&directory, 6, user("alice", Some("alice@acme.com")))
            .expect("the name and email are free again");
        assert!(
            directory.roles_of("user:alice").is_empty(),
            "a new user starts with nothing"
        );
        apply(
            &directory,
            7,
            Change::DeleteRole {
                name: "readers".to_owned(),
            },
        )
        .expect("deleted");
        apply(
            &directory,
            8,
            Change::CreateRole {
                name: "readers".to_owned(),
                description: String::new(),
                max_lifetime: None,
            },
        )
        .expect("again");
        assert!(
            directory
                .role("readers")
                .expect("the role")
                .members
                .is_empty()
        );
        drop(directory);
        assert_eq!(
            open(&root).revision(),
            8,
            "the replay reaches the same state"
        );
    }

    #[test]
    fn a_change_that_changes_nothing_writes_nothing_and_a_stale_revision_is_refused() {
        let root = scratch("idempotent");
        let directory = open(&root);
        apply(
            &directory,
            1,
            Change::CreateRole {
                name: "r".to_owned(),
                description: String::new(),
                max_lifetime: None,
            },
        )
        .expect("a role");
        apply(
            &directory,
            2,
            Change::AddMember {
                role: "r".to_owned(),
                member: "spiffe://acme/billing".to_owned(),
            },
        )
        .expect("added");
        let again = apply(
            &directory,
            3,
            Change::AddMember {
                role: "r".to_owned(),
                member: "spiffe://acme/billing".to_owned(),
            },
        )
        .expect("answered");
        assert_eq!(
            again,
            Written {
                revision: 2,
                changed: false
            }
        );
        let absent = apply(
            &directory,
            4,
            Change::RemoveMember {
                role: "r".to_owned(),
                member: "spiffe://acme/other".to_owned(),
            },
        )
        .expect("answered");
        assert!(!absent.changed);
        let stale = directory.apply(
            &Applying::for_tests(5),
            Change::DeleteRole {
                name: "r".to_owned(),
            },
            "admin",
            1,
            Some(1),
        );
        assert!(matches!(
            stale,
            Err(DirectoryError::Conflict {
                expected: 1,
                current: 2
            })
        ));
        let reused = apply(
            &directory,
            2,
            Change::DeleteRole {
                name: "r".to_owned(),
            },
        );
        assert!(
            matches!(reused, Err(DirectoryError::Invalid(_))),
            "one operation writes once"
        );
    }

    #[test]
    fn what_the_directory_would_never_hold_is_refused_before_any_write() {
        let root = scratch("refused");
        let directory = open(&root);
        apply(
            &directory,
            1,
            Change::CreateRole {
                name: "r".to_owned(),
                description: String::new(),
                max_lifetime: None,
            },
        )
        .expect("a role");
        apply(&directory, 2, user("bob", Some("bob@acme.com"))).expect("a user");
        let refused = |op: u8, change: Change| {
            let error = apply(&directory, op, change).expect_err("refused");
            assert_eq!(directory.revision(), 2, "nothing written for {error}");
            error.to_string()
        };
        assert!(
            refused(
                10,
                Change::CreateRole {
                    name: "Admins".to_owned(),
                    description: String::new(),
                    max_lifetime: None,
                }
            )
            .contains("role name")
        );
        assert!(
            refused(
                11,
                Change::CreateRole {
                    name: "r".to_owned(),
                    description: String::new(),
                    max_lifetime: None,
                }
            )
            .contains("exists")
        );
        assert!(
            refused(
                12,
                Change::AddMember {
                    role: "r".to_owned(),
                    member: "anonymous".to_owned()
                }
            )
            .contains("cannot be a member")
        );
        assert!(
            refused(
                13,
                Change::AddMember {
                    role: "r".to_owned(),
                    member: "role:r".to_owned()
                }
            )
            .contains("cannot be a member")
        );
        assert!(
            refused(
                14,
                Change::AddMember {
                    role: "r".to_owned(),
                    member: "user:ghost".to_owned()
                }
            )
            .contains("no user")
        );
        assert!(
            refused(
                15,
                Change::AddMember {
                    role: "ghost".to_owned(),
                    member: "user:bob".to_owned()
                }
            )
            .contains("no role")
        );
        assert!(refused(16, user("Bob Smith", None)).contains("user name"));
        assert!(refused(17, user("carol", Some("BOB@acme.com"))).contains("is the user `bob`'s"));
        assert!(refused(18, user("carol", Some("not-an-email"))).contains("not an email"));
        assert!(
            refused(
                19,
                Change::SetPassword {
                    name: "bob".to_owned(),
                    password: "plain".to_owned()
                }
            )
            .contains("Argon2id")
        );
        assert!(
            refused(
                20,
                Change::Link {
                    name: "bob".to_owned(),
                    subject: "spiffe://acme/bob".to_owned()
                }
            )
            .contains("provider subject")
        );
        apply(&directory, 21, user("carol", None)).expect("a user");
        apply(
            &directory,
            22,
            Change::Link {
                name: "bob".to_owned(),
                subject: "oidc:https://idp#b".to_owned(),
            },
        )
        .expect("linked");
        let taken = apply(
            &directory,
            23,
            Change::Link {
                name: "carol".to_owned(),
                subject: "oidc:https://idp#b".to_owned(),
            },
        )
        .expect_err("taken");
        assert!(taken.to_string().contains("linked to the user `bob`"));
    }

    #[test]
    fn a_status_password_and_factor_change_are_journaled() {
        let root = scratch("status");
        let directory = open(&root);
        apply(&directory, 1, user("dave", None)).expect("a user");
        apply(
            &directory,
            2,
            Change::SetStatus {
                name: "dave".to_owned(),
                active: false,
            },
        )
        .expect("disabled");
        assert!(
            !apply(
                &directory,
                3,
                Change::SetStatus {
                    name: "dave".to_owned(),
                    active: false
                }
            )
            .expect("answered")
            .changed
        );
        apply(
            &directory,
            4,
            Change::SetFactor {
                name: "dave".to_owned(),
                factor: Some(vec![1, 2, 3]),
            },
        )
        .expect("a factor");
        apply(
            &directory,
            5,
            Change::UpdateUser {
                name: "dave".to_owned(),
                email: Some("dave@acme.com".to_owned()),
                display: Some("Dave".to_owned()),
            },
        )
        .expect("updated");
        drop(directory);
        let directory = open(&root);
        let dave = directory.user("dave").expect("the user");
        assert_eq!(dave.status, UserStatus::Disabled);
        assert_eq!(dave.factor.as_deref(), Some(&[1u8, 2, 3][..]));
        assert_eq!(dave.display.as_deref(), Some("Dave"));
        assert!(
            format!("{dave:?}").contains("<set>") && !format!("{dave:?}").contains("argon2"),
            "never the hash in a debug line"
        );
        apply(
            &directory,
            6,
            Change::SetFactor {
                name: "dave".to_owned(),
                factor: None,
            },
        )
        .expect("reset");
        apply(
            &directory,
            7,
            Change::UpdateUser {
                name: "dave".to_owned(),
                email: Some(String::new()),
                display: None,
            },
        )
        .expect("cleared");
        let dave = directory.user("dave").expect("the user");
        assert!(dave.factor.is_none() && dave.email.is_none());
        assert!(directory.user_by_email("dave@acme.com").is_none());
    }

    #[test]
    fn a_transition_round_trips_and_an_unknown_label_or_kind_is_refused() {
        let mut transition = DirectoryTransition::new(kinds::USER_CREATE, "eve");
        transition.revision = 3;
        transition.at = 1_800_000_000;
        transition.by = "admin".to_owned();
        transition.operation_id = Some(OperationId::from_bytes([9; 16]));
        transition.email = Some("eve@acme.com".to_owned());
        transition.password = Some(PHC.to_owned());
        let bytes = transition.encode().expect("encodes");
        assert_eq!(
            DirectoryTransition::decode(&bytes).expect("decodes"),
            transition
        );
        let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("canonical") else {
            panic!("a map")
        };
        pairs.push((Value::Int(24), Value::Text("x".to_owned())));
        let extended = cbor::encode(&Value::Map(pairs)).expect("encodes");
        assert!(DirectoryTransition::decode(&extended).is_err());
        let unknown = DirectoryTransition::new("user.promote", "eve")
            .encode()
            .expect("encodes");
        assert!(DirectoryTransition::decode(&unknown).is_err());
    }

    /// The thumbprint of the test key, 32 bytes of 7.
    fn kid() -> String {
        super::super::credentials::thumbprint("EdDSA", &[7; 32]).expect("a thumbprint")
    }

    fn account(name: &str) -> Change {
        Change::CreateServiceAccount {
            name: name.to_owned(),
            owner: "payments team".to_owned(),
            description: "billing jobs".to_owned(),
        }
    }

    fn secret(account: &str, id: u8) -> Change {
        Change::AddCredential {
            account: account.to_owned(),
            id: [id; 16],
            material: CredentialMaterial::Secret {
                phc: PHC.to_owned(),
            },
            expires_at: None,
        }
    }

    fn bound(account: &str, id: u8, binding: &str) -> Change {
        Change::AddCredential {
            account: account.to_owned(),
            id: [id; 16],
            material: CredentialMaterial::Binding {
                binding: binding.to_owned(),
            },
            expires_at: None,
        }
    }

    /// WP-11.2: a service account, its status, its three kinds of credential and a revocation are
    /// journaled, and a reopen replays them to the same state.
    #[test]
    fn service_accounts_and_their_credentials_survive_a_reopen() {
        let root = scratch("accounts-reopen");
        let key = Change::AddCredential {
            account: "billing".to_owned(),
            id: [2; 16],
            material: CredentialMaterial::Key {
                algorithm: "EdDSA".to_owned(),
                key: vec![7; 32],
                key_id: kid(),
            },
            expires_at: Some(1_900_000_000),
        };
        let held = {
            let directory = open(&root);
            apply(&directory, 1, account("billing")).expect("an account");
            apply(&directory, 2, secret("billing", 1)).expect("a secret");
            apply(&directory, 3, key).expect("a key");
            apply(&directory, 4, bound("billing", 3, "spiffe://acme/billing")).expect("a binding");
            apply(
                &directory,
                5,
                Change::RevokeCredential {
                    account: "billing".to_owned(),
                    id: [1; 16],
                },
            )
            .expect("a revocation");
            apply(
                &directory,
                6,
                Change::SetAccountStatus {
                    name: "billing".to_owned(),
                    active: false,
                },
            )
            .expect("suspended");
            apply(
                &directory,
                7,
                Change::UpdateServiceAccount {
                    name: "billing".to_owned(),
                    owner: Some("platform team".to_owned()),
                    description: None,
                },
            )
            .expect("updated");
            directory.service_account("billing").expect("held")
        };
        let directory = open(&root);
        let reopened = directory.service_account("billing").expect("replayed");
        assert_eq!(reopened, held);
        assert_eq!(reopened.status, AccountStatus::Suspended);
        assert_eq!(reopened.owner, "platform team");
        assert_eq!(reopened.description, "billing jobs");
        assert_eq!(reopened.credentials.len(), 3);
        assert_eq!(reopened.credentials[0].revoked_at, Some(1_800_000_000));
        assert_eq!(reopened.credentials[1].created_revision, 3);
        assert_eq!(reopened.live_credentials(1_800_000_000).count(), 2);
        // The key expires: at its expiry it is no longer live.
        assert_eq!(reopened.live_credentials(1_900_000_000).count(), 1);
        assert_eq!(
            directory
                .account_of_binding("spiffe://acme/billing")
                .map(|account| account.name),
            Some("billing".to_owned())
        );
    }

    /// The bound of 8 counts live credentials only: a revoked one makes room for the next.
    #[test]
    fn at_most_eight_live_credentials_and_a_revoked_one_makes_room() {
        let directory = open(&scratch("accounts-bound"));
        apply(&directory, 1, account("billing")).expect("an account");
        for id in 0..8u8 {
            apply(&directory, 10 + id, secret("billing", id)).expect("a credential");
        }
        let refused = apply(&directory, 30, secret("billing", 8)).expect_err("a ninth");
        assert!(
            refused.to_string().contains("8 live credentials"),
            "{refused}"
        );
        apply(
            &directory,
            31,
            Change::RevokeCredential {
                account: "billing".to_owned(),
                id: [0; 16],
            },
        )
        .expect("revoked");
        apply(&directory, 32, secret("billing", 8)).expect("room again");
        // Revoking twice writes nothing.
        let again = apply(
            &directory,
            33,
            Change::RevokeCredential {
                account: "billing".to_owned(),
                id: [0; 16],
            },
        )
        .expect("idempotent");
        assert!(!again.changed);
    }

    /// Past MAX_CREDENTIALS kept, the oldest credential that proves nothing is dropped: a
    /// rotation never runs out of room, and every live credential stays.
    #[test]
    fn the_oldest_dead_credentials_make_room_for_a_rotation() {
        let directory = open(&scratch("accounts-rotation"));
        apply(&directory, 1, account("billing")).expect("an account");
        let mut op = 0u64;
        let mut next = |directory: &Directory, change: Change| {
            op += 1;
            directory.apply(
                &Applying::for_tests_numbered(op),
                change,
                "admin",
                1_800_000_000,
                None,
            )
        };
        // Two keys stay live throughout; every secret is made and revoked.
        let live_secret = |id: u8| Change::AddCredential {
            account: "billing".to_owned(),
            id: [id; 16],
            material: CredentialMaterial::Secret {
                phc: PHC.to_owned(),
            },
            expires_at: None,
        };
        next(&directory, live_secret(0)).expect("live");
        let mut id = [0u8; 16];
        for round in 0..300u16 {
            id[..2].copy_from_slice(&(round + 1).to_be_bytes());
            next(
                &directory,
                Change::AddCredential {
                    account: "billing".to_owned(),
                    id,
                    material: CredentialMaterial::Secret {
                        phc: PHC.to_owned(),
                    },
                    expires_at: None,
                },
            )
            .expect("room for a rotation");
            next(
                &directory,
                Change::RevokeCredential {
                    account: "billing".to_owned(),
                    id,
                },
            )
            .expect("revoked");
        }
        let held = directory.service_account("billing").expect("held");
        assert_eq!(held.credentials.len(), MAX_CREDENTIALS);
        assert!(
            held.credentials
                .iter()
                .any(|credential| credential.id == [0; 16])
        );
        assert_eq!(held.live_credentials(1_800_000_000).count(), 1);
    }

    /// One binding names one account; revoking it frees it, and deleting the account frees its
    /// bindings and removes it from every role.
    #[test]
    fn a_binding_names_one_account_and_deleting_an_account_frees_it() {
        let directory = open(&scratch("accounts-bindings"));
        apply(&directory, 1, account("billing")).expect("an account");
        apply(&directory, 2, account("reports")).expect("another");
        apply(&directory, 3, bound("billing", 1, "spiffe://acme/jobs")).expect("bound");
        let taken =
            apply(&directory, 4, bound("reports", 2, "spiffe://acme/jobs")).expect_err("taken");
        assert!(matches!(taken, DirectoryError::Exists(_)), "{taken}");
        apply(
            &directory,
            5,
            Change::RevokeCredential {
                account: "billing".to_owned(),
                id: [1; 16],
            },
        )
        .expect("revoked");
        assert!(directory.account_of_binding("spiffe://acme/jobs").is_none());
        apply(&directory, 6, bound("reports", 2, "spiffe://acme/jobs")).expect("free again");
        apply(
            &directory,
            7,
            Change::CreateRole {
                name: "readers".to_owned(),
                description: String::new(),
                max_lifetime: None,
            },
        )
        .expect("a role");
        apply(
            &directory,
            8,
            Change::AddMember {
                role: "readers".to_owned(),
                member: "sa:reports".to_owned(),
            },
        )
        .expect("a member");
        let unknown = apply(
            &directory,
            9,
            Change::AddMember {
                role: "readers".to_owned(),
                member: "sa:nobody".to_owned(),
            },
        )
        .expect_err("no such account");
        assert!(matches!(unknown, DirectoryError::NotFound(_)), "{unknown}");
        apply(
            &directory,
            10,
            Change::DeleteServiceAccount {
                name: "reports".to_owned(),
            },
        )
        .expect("deleted");
        assert!(directory.account_of_binding("spiffe://acme/jobs").is_none());
        assert!(directory.roles_of("sa:reports").is_empty());
        assert!(directory.service_account("reports").is_none());
    }

    #[test]
    fn a_bad_account_or_credential_is_refused_before_anything_is_written() {
        let directory = open(&scratch("accounts-refused"));
        apply(&directory, 1, account("billing")).expect("an account");
        let mut refusals = vec![
            account("Billing"),
            account("billing"),
            Change::CreateServiceAccount {
                name: "jobs".to_owned(),
                owner: " ".to_owned(),
                description: String::new(),
            },
            secret("nobody", 1),
            Change::AddCredential {
                account: "billing".to_owned(),
                id: [1; 16],
                material: CredentialMaterial::Secret {
                    phc: "plain".to_owned(),
                },
                expires_at: None,
            },
            Change::AddCredential {
                account: "billing".to_owned(),
                id: [1; 16],
                material: CredentialMaterial::Secret {
                    phc: PHC.to_owned(),
                },
                expires_at: Some(1_700_000_000),
            },
            Change::AddCredential {
                account: "billing".to_owned(),
                id: [1; 16],
                material: CredentialMaterial::Key {
                    algorithm: "ES256".to_owned(),
                    key: vec![4; 32],
                    key_id: "kid".to_owned(),
                },
                expires_at: None,
            },
            bound("billing", 1, "not a binding"),
            Change::AddCredential {
                account: "billing".to_owned(),
                id: [1; 16],
                material: CredentialMaterial::Key {
                    algorithm: "EdDSA".to_owned(),
                    key: vec![7; 32],
                    key_id: "the caller's own kid".to_owned(),
                },
                expires_at: None,
            },
            Change::AddCredential {
                account: "billing".to_owned(),
                id: [1; 16],
                material: CredentialMaterial::Key {
                    algorithm: "EdDSA".to_owned(),
                    key: vec![0; 32],
                    key_id: super::super::credentials::thumbprint("EdDSA", &[0; 32])
                        .expect("a thumbprint"),
                },
                expires_at: None,
            },
            Change::RevokeCredential {
                account: "billing".to_owned(),
                id: [9; 16],
            },
        ];
        for (op, change) in refusals.drain(..).enumerate() {
            let op = u8::try_from(op + 10).expect("small");
            assert!(apply(&directory, op, change.clone()).is_err(), "{change:?}");
        }
        assert_eq!(directory.revision(), 1);
        // One key once per account.
        let key = |id| Change::AddCredential {
            account: "billing".to_owned(),
            id: [id; 16],
            material: CredentialMaterial::Key {
                algorithm: "EdDSA".to_owned(),
                key: vec![7; 32],
                key_id: kid(),
            },
            expires_at: None,
        };
        apply(&directory, 40, key(1)).expect("a key");
        assert!(apply(&directory, 41, key(2)).is_err());
        assert!(apply(&directory, 42, key(1)).is_err(), "an id once");
    }

    #[test]
    fn a_transition_never_shows_a_password_factor_or_secret_hash() {
        let mut transition = DirectoryTransition::new(kinds::CREDENTIAL_ADD, "billing");
        transition.secret = Some(PHC.to_owned());
        transition.password = Some(PHC.to_owned());
        transition.factor = Some(vec![42; 8]);
        let shown = format!("{transition:?}");
        assert!(
            !shown.contains("argon2") && !shown.contains("42, 42"),
            "{shown}"
        );
        assert!(shown.contains("<set>"));
    }

    #[test]
    fn a_service_account_transition_round_trips_with_every_label() {
        let mut transition = DirectoryTransition::new(kinds::CREDENTIAL_ADD, "billing");
        transition.revision = 4;
        transition.at = 1_800_000_000;
        transition.by = "admin".to_owned();
        transition.credential_id = Some([5; 16]);
        transition.credential_kind = Some("private_key_jwt".to_owned());
        transition.public_key = Some(vec![7; 32]);
        transition.algorithm = Some("EdDSA".to_owned());
        transition.key_id = Some("kid".to_owned());
        transition.expires_at = Some(1_900_000_000);
        let bytes = transition.encode().expect("encodes");
        assert_eq!(
            DirectoryTransition::decode(&bytes).expect("decodes"),
            transition
        );
        let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("canonical") else {
            panic!("a map")
        };
        for pair in &mut pairs {
            if pair.0 == Value::Int(16) {
                pair.1 = Value::Bytes(vec![5; 15]);
            }
        }
        let short = cbor::encode(&Value::Map(pairs)).expect("encodes");
        assert!(DirectoryTransition::decode(&short).is_err(), "a short id");
    }
}
