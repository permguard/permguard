// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The service accounts (`2-security/8` Service accounts): their scopes and access keys, in one
//! journal on the volume.
//!
//! ```text
//! planes/authority/accounts/journal/     one frame per change: the account as it stands after it
//! ```
//!
//! A frame is a closed CBOR map with integer labels (`contracts/cbor/authority.json`):
//!
//! | Label | Member         | Type                         |
//! | ----- | -------------- | ---------------------------- |
//! | 1     | `name`         | text                         |
//! | 2     | `revision`     | uint                         |
//! | 3     | `at`           | uint, seconds                |
//! | 4     | `by`           | text                         |
//! | 5     | `operation_id` | bytes, 16, optional          |
//! | 6     | `status`       | `active`, `suspended`, `deleted` |
//! | 7     | `description`  | text, optional               |
//! | 8     | `scopes`       | array of `{1 operations, 2 selector}` |
//! | 9     | `keys`         | array of `{1 access_key, 2 secret_hash, 3 created_at, 4? expires_at}` |
//! | 10    | `created_at`   | uint, seconds, optional      |
//!
//! The journal is the truth and is replayed whole at open: the last frame of a name is the
//! account. A secret key is kept as its Argon2id hash and nothing else.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use permguard_core::authz::{
    MAX_TOKEN_SCOPES, Resource, Selector, TokenScope, operation_fits, operations,
};
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::{Applying, Domain, Observed};
use permguard_host::storage::StorageError;
use permguard_host::storage::dir::Dir;
use permguard_host::storage::journal::{Journal, Options, Recovery};
use permguard_objects::cbor::Value;

use crate::cbor::{self, RecordError};

/// The directory below `planes/authority/`.
pub const DIRECTORY: &str = "accounts";
const JOURNAL: &str = "journal";
const FRAME_ACCOUNT: u16 = 1;
/// The domain the accounts' mutations run in.
pub const DOMAIN: &str = "authority.accounts";
/// The administrator every Authority Plane makes at its first start.
pub const ADMIN: &str = "admin";
/// The most accounts one Authority Plane holds.
pub const MAX_ACCOUNTS: usize = 10_000;
/// The most live access keys of one account: room for a rotation's overlap, no more.
pub const MAX_LIVE_KEYS: usize = 2;
/// The longest description, in bytes.
pub const MAX_DESCRIPTION: usize = 1_024;
/// The principal of the account `name`.
pub fn principal_of(name: &str) -> String {
    format!("sa:{name}")
}

/// Whether an account may obtain tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Suspended,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// One access key of an account; its secret only as a hash.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessKey {
    pub access_key: String,
    pub secret_hash: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl std::fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessKey")
            .field("access_key", &self.access_key)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl AccessKey {
    /// Whether the key may obtain a token at `now`.
    pub fn is_live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|expires| now < expires)
    }
}

/// One service account, as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub description: String,
    pub status: Status,
    pub scopes: Vec<TokenScope>,
    pub keys: Vec<AccessKey>,
    pub created_at: u64,
    pub updated_at: u64,
    /// The journal revision of its last change.
    pub revision: u64,
}

impl Account {
    /// A new active account with no key.
    pub fn new(name: &str, description: &str, scopes: Vec<TokenScope>, now: u64) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            status: Status::Active,
            scopes,
            keys: Vec::new(),
            created_at: now,
            updated_at: now,
            revision: 0,
        }
    }

    /// Whether it is the administrator: never deleted, suspended or narrowed.
    pub fn is_admin(&self) -> bool {
        self.name == ADMIN
    }

    /// Its keys live at `now`.
    pub fn live_keys(&self, now: u64) -> impl Iterator<Item = &AccessKey> {
        self.keys.iter().filter(move |key| key.is_live(now))
    }

    /// The key `access_key` names.
    pub fn key(&self, access_key: &str) -> Option<&AccessKey> {
        self.keys.iter().find(|key| key.access_key == access_key)
    }
}

/// The administrator's scopes: every registered operation on every resource, one scope per
/// resource kind so each stays coherent.
pub fn admin_scopes() -> Vec<TokenScope> {
    [
        Resource::host(),
        Resource::plane("authority"),
        Resource::plane("control"),
        Resource::plane("data"),
    ]
    .into_iter()
    .map(|resource| {
        let selector = Selector::under(resource);
        TokenScope {
            operations: operations::ALL
                .iter()
                .filter(|operation| operation_fits(operation, &selector))
                .map(|operation| (*operation).to_owned())
                .collect(),
            selector,
        }
    })
    .collect()
}

/// Checks an account name: 1 to 63 lowercase letters, digits, `-`, `_`, `.`, starting with a
/// letter or a digit.
pub fn check_name(name: &str) -> Result<(), String> {
    let valid = (1..=63).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(format!(
            "`{name}` is not an account name: 1 to 63 of a-z, 0-9, `-`, `_` and `.`, starting \
             with a letter or a digit"
        ))
    }
}

/// Checks a description: at most [`MAX_DESCRIPTION`] bytes, no control character.
pub fn check_description(description: &str) -> Result<(), String> {
    if description.len() > MAX_DESCRIPTION {
        return Err(format!(
            "a description takes at most {MAX_DESCRIPTION} bytes"
        ));
    }
    if description.chars().any(char::is_control) {
        return Err("a description holds no control character".to_owned());
    }
    Ok(())
}

/// Checks a set of scopes: at most [`MAX_TOKEN_SCOPES`], each naming registered operations
/// only, every one of which fits its selector (`2-security/6` Scope coherence).
pub fn check_scopes(scopes: &[TokenScope]) -> Result<(), String> {
    if scopes.len() > MAX_TOKEN_SCOPES {
        return Err(format!(
            "an account holds at most {MAX_TOKEN_SCOPES} scopes"
        ));
    }
    for (position, scope) in scopes.iter().enumerate() {
        if scope.operations.is_empty() {
            return Err(format!("scope {position} names no operation"));
        }
        for operation in &scope.operations {
            if !operations::is_registered(operation) {
                return Err(format!(
                    "scope {position} names `{operation}`, which is not a registered operation"
                ));
            }
            if !operation_fits(operation, &scope.selector) {
                return Err(format!(
                    "scope {position}: `{operation}` never applies under `{}`",
                    scope.selector
                ));
            }
        }
    }
    Ok(())
}

/// What the store refuses.
#[derive(Debug)]
pub enum AccountsError {
    /// A request the store would never write.
    Invalid(String),
    /// What the change needs is not there.
    NotFound(String),
    /// What the change would make collides with what is there.
    Conflict(String),
    Storage(StorageError),
    Record(RecordError),
}

impl std::fmt::Display for AccountsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) | Self::NotFound(detail) | Self::Conflict(detail) => {
                f.write_str(detail)
            }
            Self::Storage(error) => write!(f, "{error}"),
            Self::Record(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AccountsError {}

impl From<StorageError> for AccountsError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<RecordError> for AccountsError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// One journaled frame: the account after a change, or its deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    pub name: String,
    pub revision: u64,
    pub at: u64,
    pub by: String,
    pub operation_id: Option<OperationId>,
    /// `None` for a deletion.
    pub account: Option<Account>,
}

fn scope_value(scope: &TokenScope) -> Value {
    cbor::map(vec![
        (1, Some(cbor::texts(scope.operations.iter()))),
        (2, Some(Value::Text(scope.selector.to_string()))),
    ])
}

fn scope_of(value: Value) -> Result<TokenScope, RecordError> {
    let mut read = cbor::Labelled::new(value, 2)?;
    let operations = read
        .array(1, cbor::text_of)?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let selector = Selector::parse(&read.text(2)?)
        .map_err(|error| RecordError::Malformed(format!("a scope's selector: {error}")))?;
    read.finish()?;
    Ok(TokenScope {
        operations,
        selector,
    })
}

fn key_value(key: &AccessKey) -> Result<Value, RecordError> {
    Ok(cbor::map(vec![
        (1, Some(Value::Text(key.access_key.clone()))),
        (2, Some(Value::Text(key.secret_hash.clone()))),
        (3, Some(cbor::uint(key.created_at)?)),
        (4, key.expires_at.map(cbor::uint).transpose()?),
    ]))
}

fn key_of(value: Value) -> Result<AccessKey, RecordError> {
    let mut read = cbor::Labelled::new(value, 4)?;
    let key = AccessKey {
        access_key: read.text(1)?,
        secret_hash: read.text(2)?,
        created_at: read.uint(3)?,
        expires_at: read.optional_uint(4)?,
    };
    read.finish()?;
    Ok(key)
}

impl AccountRecord {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let account = self.account.as_ref();
        let status = account.map_or("deleted", |account| account.status.as_str());
        let value = cbor::map(vec![
            (1, Some(Value::Text(self.name.clone()))),
            (2, Some(cbor::uint(self.revision)?)),
            (3, Some(cbor::uint(self.at)?)),
            (4, Some(Value::Text(self.by.clone()))),
            (
                5,
                self.operation_id
                    .map(|id| Value::Bytes(id.as_bytes().to_vec())),
            ),
            (6, Some(Value::Text(status.to_owned()))),
            (
                7,
                account.map(|account| Value::Text(account.description.clone())),
            ),
            (
                8,
                account
                    .map(|account| Value::Array(account.scopes.iter().map(scope_value).collect())),
            ),
            (
                9,
                account
                    .map(|account| {
                        account
                            .keys
                            .iter()
                            .map(key_value)
                            .collect::<Result<Vec<_>, _>>()
                            .map(Value::Array)
                    })
                    .transpose()?,
            ),
            (
                10,
                account
                    .map(|account| cbor::uint(account.created_at))
                    .transpose()?,
            ),
        ]);
        cbor::encode(&value)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut read = cbor::decode(bytes, 10)?;
        let name = read.text(1)?;
        let revision = read.uint(2)?;
        let at = read.uint(3)?;
        let by = read.text(4)?;
        let operation_id = read.optional_operation_id(5)?;
        let status = read.text(6)?;
        let description = read.optional_text(7)?;
        let scopes = read.array(8, scope_of)?;
        let keys = read.array(9, key_of)?;
        let created_at = read.optional_uint(10)?;
        read.finish()?;
        let account = match status.as_str() {
            "deleted" => None,
            "active" | "suspended" => Some(Account {
                name: name.clone(),
                description: description.unwrap_or_default(),
                status: if status == "active" {
                    Status::Active
                } else {
                    Status::Suspended
                },
                scopes,
                keys,
                created_at: created_at.unwrap_or(at),
                updated_at: at,
                revision,
            }),
            other => {
                return Err(RecordError::Malformed(format!(
                    "`{other}` is not an account status"
                )));
            }
        };
        Ok(Self {
            name,
            revision,
            at,
            by,
            operation_id,
            account,
        })
    }
}

#[derive(Default)]
struct State {
    accounts: BTreeMap<String, Account>,
    revision: u64,
    operations: BTreeMap<OperationId, (u64, String)>,
}

fn apply(state: &mut State, frame: AccountRecord) -> Result<(), AccountsError> {
    if frame.revision != state.revision + 1 {
        return Err(AccountsError::Record(RecordError::Malformed(format!(
            "the accounts journal at revision {} follows revision {}",
            frame.revision, state.revision
        ))));
    }
    state.revision = frame.revision;
    if let Some(id) = frame.operation_id {
        state
            .operations
            .insert(id, (frame.revision, frame.name.clone()));
    }
    match frame.account {
        Some(account) => {
            state.accounts.insert(frame.name, account);
        }
        None => {
            state.accounts.remove(&frame.name);
        }
    }
    Ok(())
}

/// The accounts of one Authority Plane.
pub struct Accounts {
    journal: Mutex<Journal>,
    state: RwLock<State>,
}

impl std::fmt::Debug for Accounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accounts")
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

impl Accounts {
    /// Opens the accounts under `dir`, the plane's directory, replaying the journal.
    pub fn open(dir: &Dir, options: Options) -> Result<(Arc<Self>, Recovery), AccountsError> {
        let journal_dir = dir.subdir(DIRECTORY, true)?.subdir(JOURNAL, true)?;
        let (journal, recovery) = Journal::open(journal_dir, options)?;
        let mut state = State::default();
        for frame in journal.frames()? {
            if frame.kind != FRAME_ACCOUNT {
                return Err(AccountsError::Record(RecordError::Malformed(format!(
                    "the accounts journal holds a frame of kind {}",
                    frame.kind
                ))));
            }
            apply(&mut state, AccountRecord::decode(&frame.payload)?)?;
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

    /// The journal revision: the number of changes applied.
    pub fn revision(&self) -> u64 {
        self.read().revision
    }

    /// The account `name`, while held.
    pub fn get(&self, name: &str) -> Option<Account> {
        self.read().accounts.get(name).cloned()
    }

    /// Every account, by name.
    pub fn list(&self) -> Vec<Account> {
        self.read().accounts.values().cloned().collect()
    }

    /// How many accounts are held.
    pub fn len(&self) -> usize {
        self.read().accounts.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.read().accounts.is_empty()
    }

    /// The account holding `access_key`, and the key.
    pub fn by_access_key(&self, access_key: &str) -> Option<(Account, AccessKey)> {
        self.read().accounts.values().find_map(|account| {
            account
                .key(access_key)
                .map(|key| (account.clone(), key.clone()))
        })
    }

    /// The revision `operation_id` produced and the account it named, when the journal holds it.
    pub fn operation(&self, operation_id: &OperationId) -> Option<(u64, String)> {
        self.read().operations.get(operation_id).cloned()
    }

    fn write(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        account: Option<Account>,
        by: &str,
        now: u64,
    ) -> Result<Option<Account>, AccountsError> {
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(id) = applying.map(Applying::operation_id)
            && state.operations.contains_key(&id)
        {
            return Err(AccountsError::Conflict(
                "this operation already changed an account".to_owned(),
            ));
        }
        let revision = state.revision + 1;
        let account = account.map(|account| Account {
            updated_at: now,
            revision,
            ..account
        });
        let frame = AccountRecord {
            name: name.to_owned(),
            revision,
            at: now,
            by: by.to_owned(),
            operation_id: applying.map(Applying::operation_id),
            account: account.clone(),
        };
        let bytes = frame.encode()?;
        journal.append(FRAME_ACCOUNT, &bytes)?;
        apply(&mut state, frame)?;
        Ok(account)
    }

    /// Writes `account` as it stands now, a new one or a change, inside the operation `applying`
    /// names when one does; the offline commands and the first start write with none.
    pub fn put(
        &self,
        applying: Option<&Applying<'_>>,
        account: Account,
        by: &str,
        now: u64,
    ) -> Result<Account, AccountsError> {
        check_name(&account.name).map_err(AccountsError::Invalid)?;
        check_description(&account.description).map_err(AccountsError::Invalid)?;
        check_scopes(&account.scopes).map_err(AccountsError::Invalid)?;
        if account.live_keys(now).count() > MAX_LIVE_KEYS {
            return Err(AccountsError::Conflict(format!(
                "an account holds at most {MAX_LIVE_KEYS} live access keys: delete one first"
            )));
        }
        {
            let state = self.read();
            if !state.accounts.contains_key(&account.name) && state.accounts.len() >= MAX_ACCOUNTS {
                return Err(AccountsError::Conflict(format!(
                    "the Authority Plane holds at most {MAX_ACCOUNTS} service accounts"
                )));
            }
            // An access key names one key of one account, ever.
            for key in &account.keys {
                if state
                    .accounts
                    .values()
                    .any(|other| other.name != account.name && other.key(&key.access_key).is_some())
                {
                    return Err(AccountsError::Conflict(format!(
                        "the access key {} belongs to another account",
                        key.access_key
                    )));
                }
            }
        }
        let name = account.name.clone();
        let written = self.write(applying, &name, Some(account), by, now)?;
        written.ok_or(AccountsError::NotFound(name))
    }

    /// Deletes the account `name`, its keys with it.
    pub fn delete(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        by: &str,
        now: u64,
    ) -> Result<(), AccountsError> {
        let account = self
            .get(name)
            .ok_or_else(|| AccountsError::NotFound(format!("no service account `{name}`")))?;
        if account.is_admin() {
            return Err(AccountsError::Conflict(
                "`admin` is never deleted: there is always one account that can repair the \
                 others"
                    .to_owned(),
            ));
        }
        self.write(applying, name, None, by, now).map(|_| ())
    }
}

/// The accounts, as recovery of the mutation journal sees them.
pub struct Recovering<'a>(pub &'a Accounts);

impl Domain for Recovering<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, _target: Option<&str>) -> Option<Observed> {
        self.0
            .operation(operation_id)
            .map(|(revision, name)| Observed {
                revision,
                target: Some(name),
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> Dir {
        let root = std::env::temp_dir().join(format!(
            "pg-authority-accounts-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        Dir::open(&root).expect("a directory")
    }

    fn scope(operations: &[&str], selector: &str) -> TokenScope {
        TokenScope {
            operations: operations.iter().map(|op| (*op).to_owned()).collect(),
            selector: Selector::parse(selector).expect("a selector"),
        }
    }

    fn key(id: &str) -> AccessKey {
        AccessKey {
            access_key: id.to_owned(),
            secret_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            created_at: 10,
            expires_at: None,
        }
    }

    #[test]
    fn accounts_survive_a_reopen_and_the_last_frame_of_a_name_is_the_account() {
        let dir = scratch("reopen");
        let (accounts, _) = Accounts::open(&dir, Options::default()).expect("opens");
        let billing = Account::new(
            "billing",
            "the billing service",
            vec![scope(&[operations::DECISION_EVALUATE], "plane/data/*")],
            10,
        );
        let written = accounts.put(None, billing, "test", 10).expect("written");
        assert_eq!(written.revision, 1);
        let mut changed = written.clone();
        changed.status = Status::Suspended;
        changed.keys.push(key("pgak_AAAAAAAAAAAAAAAAAAAA"));
        accounts.put(None, changed, "test", 20).expect("changed");
        accounts
            .put(None, Account::new("gone", "", Vec::new(), 30), "test", 30)
            .expect("written");
        accounts.delete(None, "gone", "test", 40).expect("deleted");
        drop(accounts);
        let (reopened, _) = Accounts::open(&dir, Options::default()).expect("reopens");
        assert_eq!(reopened.revision(), 4);
        let held = reopened.get("billing").expect("held");
        assert_eq!(held.status, Status::Suspended);
        assert_eq!(held.created_at, 10);
        assert_eq!(held.updated_at, 20);
        assert_eq!(held.scopes.len(), 1);
        assert!(reopened.get("gone").is_none());
        assert_eq!(
            reopened
                .by_access_key("pgak_AAAAAAAAAAAAAAAAAAAA")
                .expect("found")
                .0
                .name,
            "billing"
        );
    }

    #[test]
    fn what_the_store_would_never_hold_is_refused() {
        let dir = scratch("refused");
        let (accounts, _) = Accounts::open(&dir, Options::default()).expect("opens");
        for bad in ["", "Upper", "-dash", &"a".repeat(64), "sp ace"] {
            assert!(
                accounts
                    .put(None, Account::new(bad, "", Vec::new(), 1), "t", 1)
                    .is_err(),
                "{bad:?}"
            );
        }
        // An operation outside the registry, or one that never applies where it is placed.
        for scopes in [
            vec![scope(&["nothing.at.all"], "plane/data/*")],
            vec![scope(&[operations::DECISION_EVALUATE], "plane/control/*")],
            vec![scope(&[], "plane/data/*")],
        ] {
            assert!(
                accounts
                    .put(None, Account::new("a", "", scopes, 1), "t", 1)
                    .is_err()
            );
        }
        let mut three = Account::new("three", "", Vec::new(), 1);
        three.keys = vec![
            key("pgak_AAAAAAAAAAAAAAAAAAAA"),
            key("pgak_BBBBBBBBBBBBBBBBBBBB"),
            key("pgak_CCCCCCCCCCCCCCCCCCCC"),
        ];
        assert!(matches!(
            accounts.put(None, three, "t", 1),
            Err(AccountsError::Conflict(_))
        ));
        let mut one = Account::new("one", "", Vec::new(), 1);
        one.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
        accounts.put(None, one, "t", 1).expect("written");
        let mut other = Account::new("other", "", Vec::new(), 1);
        other.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
        assert!(matches!(
            accounts.put(None, other, "t", 1),
            Err(AccountsError::Conflict(_))
        ));
        accounts
            .put(None, Account::new(ADMIN, "", admin_scopes(), 1), "t", 1)
            .expect("the administrator");
        assert!(matches!(
            accounts.delete(None, ADMIN, "t", 2),
            Err(AccountsError::Conflict(_))
        ));
    }

    #[test]
    fn the_administrators_scopes_are_coherent_and_reach_every_plane() {
        let scopes = admin_scopes();
        check_scopes(&scopes).expect("coherent");
        let reaches = |operation: &str, resource: &Resource| {
            scopes.iter().any(|scope| {
                scope.operations.contains(operation) && scope.selector.contains(resource)
            })
        };
        assert!(reaches(
            operations::ACCOUNTS_WRITE,
            &Resource::plane("authority")
        ));
        assert!(reaches(
            operations::DECISION_EVALUATE,
            &Resource::ledger("data", "z", "l")
        ));
        assert!(reaches(
            operations::CATALOG_WRITE,
            &Resource::zone("control", "z")
        ));
        assert!(reaches(operations::MEMBERSHIP_ADMIN, &Resource::host()));
        for operation in operations::ALL {
            assert!(
                scopes
                    .iter()
                    .any(|scope| scope.operations.contains(*operation)),
                "{operation}"
            );
        }
    }
}
