// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The accounts on the file backend: one journal on the volume.
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
//! account. A secret key is kept as its Argon2id hash and nothing else. The state replayed is
//! this backend's own: every rule of [`AccountStore`] is judged and written under the journal's
//! lock, so the state in memory never holds what the journal does not.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use permguard_core::authz::{Selector, TokenScope};
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::Applying;
use permguard_host::storage::StorageError;
use permguard_host::storage::dir::Dir;
use permguard_host::storage::journal::{Journal, Options, Recovery};
use permguard_objects::cbor::Value;

use super::{AccessKey, Account, AccountStore, AccountsError, MAX_ACCOUNTS, Status, validate};
use crate::cbor::{self, RecordError};

/// The directory below `planes/authority/`.
pub const DIRECTORY: &str = "accounts";
const JOURNAL: &str = "journal";
const FRAME_ACCOUNT: u16 = 1;

impl From<StorageError> for AccountsError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

impl From<RecordError> for AccountsError {
    fn from(error: RecordError) -> Self {
        Self::Unavailable(error.to_string())
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
        return Err(RecordError::Malformed(format!(
            "the accounts journal at revision {} follows revision {}",
            frame.revision, state.revision
        ))
        .into());
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

/// The accounts of one Authority Plane, on its volume.
pub struct FileAccounts {
    journal: Mutex<Journal>,
    state: RwLock<State>,
}

impl std::fmt::Debug for FileAccounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAccounts")
            .field("revision", &self.read().revision)
            .finish_non_exhaustive()
    }
}

impl FileAccounts {
    /// Opens the accounts under `dir`, the plane's directory, replaying the journal.
    pub fn open(dir: &Dir, options: Options) -> Result<(Arc<Self>, Recovery), AccountsError> {
        let journal_dir = dir.subdir(DIRECTORY, true)?.subdir(JOURNAL, true)?;
        let (journal, recovery) = Journal::open(journal_dir, options)?;
        let mut state = State::default();
        for frame in journal.frames()? {
            if frame.kind != FRAME_ACCOUNT {
                return Err(RecordError::Malformed(format!(
                    "the accounts journal holds a frame of kind {}",
                    frame.kind
                ))
                .into());
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

    /// Appends one frame and applies it; the caller holds both locks, so what it judged is
    /// what the frame follows.
    fn write(
        journal: &mut Journal,
        state: &mut State,
        applying: Option<&Applying<'_>>,
        name: &str,
        account: Option<Account>,
        by: &str,
        now: u64,
    ) -> Result<Option<Account>, AccountsError> {
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
        apply(state, frame)?;
        Ok(account)
    }
}

impl AccountStore for FileAccounts {
    fn revision(&self) -> Result<u64, AccountsError> {
        Ok(self.read().revision)
    }

    fn get(&self, name: &str) -> Result<Option<Account>, AccountsError> {
        Ok(self.read().accounts.get(name).cloned())
    }

    fn list(&self) -> Result<Vec<Account>, AccountsError> {
        Ok(self.read().accounts.values().cloned().collect())
    }

    fn count(&self) -> Result<usize, AccountsError> {
        Ok(self.read().accounts.len())
    }

    fn by_access_key(
        &self,
        access_key: &str,
    ) -> Result<Option<(Account, AccessKey)>, AccountsError> {
        Ok(self.read().accounts.values().find_map(|account| {
            account
                .key(access_key)
                .map(|key| (account.clone(), key.clone()))
        }))
    }

    fn operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<(u64, String)>, AccountsError> {
        Ok(self.read().operations.get(operation_id).cloned())
    }

    fn create(
        &self,
        applying: Option<&Applying<'_>>,
        account: Account,
        by: &str,
        now: u64,
    ) -> Result<Account, AccountsError> {
        validate(&account, now)?;
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        if state.accounts.contains_key(&account.name) {
            return Err(AccountsError::Conflict(format!(
                "the service account `{}` exists",
                account.name
            )));
        }
        if state.accounts.len() >= MAX_ACCOUNTS {
            return Err(AccountsError::Conflict(format!(
                "the Authority Plane holds at most {MAX_ACCOUNTS} service accounts"
            )));
        }
        key_of_another(&state, &account)?;
        let name = account.name.clone();
        let written = Self::write(
            &mut journal,
            &mut state,
            applying,
            &name,
            Some(account),
            by,
            now,
        )?;
        written.ok_or(AccountsError::NotFound(name))
    }

    fn update(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        change: &dyn Fn(&Account) -> Result<Account, AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<Account, AccountsError> {
        // Both locks are held from the read to the write: the account `change` is given is the
        // one its answer replaces.
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let held = state
            .accounts
            .get(name)
            .ok_or_else(|| AccountsError::NotFound(format!("no service account `{name}`")))?;
        let changed = Account {
            name: held.name.clone(),
            created_at: held.created_at,
            ..change(held)?
        };
        validate(&changed, now)?;
        key_of_another(&state, &changed)?;
        let written = Self::write(
            &mut journal,
            &mut state,
            applying,
            name,
            Some(changed),
            by,
            now,
        )?;
        written.ok_or_else(|| AccountsError::NotFound(name.to_owned()))
    }

    fn delete(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        allow: &dyn Fn(&Account) -> Result<(), AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<(), AccountsError> {
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let account = state
            .accounts
            .get(name)
            .ok_or_else(|| AccountsError::NotFound(format!("no service account `{name}`")))?;
        if account.is_admin() {
            return Err(AccountsError::Conflict(
                "`admin` is never deleted: there is always one account that can repair the \
                 others"
                    .to_owned(),
            ));
        }
        allow(account)?;
        Self::write(&mut journal, &mut state, applying, name, None, by, now).map(|_| ())
    }
}

/// Refuses an access key of `account` that another account holds: a key names one key of one
/// account.
fn key_of_another(state: &State, account: &Account) -> Result<(), AccountsError> {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::authz::operations;

    use super::super::{ADMIN, admin_scopes};
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
        let (accounts, _) = FileAccounts::open(&dir, Options::default()).expect("opens");
        let billing = Account::new(
            "billing",
            "the billing service",
            vec![scope(&[operations::DECISION_EVALUATE], "plane/data/*")],
            10,
        );
        let written = accounts.create(None, billing, "test", 10).expect("written");
        assert_eq!(written.revision, 1);
        accounts
            .update(
                None,
                "billing",
                &|held| {
                    let mut changed = held.clone();
                    changed.status = Status::Suspended;
                    changed.keys.push(key("pgak_AAAAAAAAAAAAAAAAAAAA"));
                    Ok(changed)
                },
                "test",
                20,
            )
            .expect("changed");
        accounts
            .create(None, Account::new("gone", "", Vec::new(), 30), "test", 30)
            .expect("written");
        accounts
            .delete(None, "gone", &|_| Ok(()), "test", 40)
            .expect("deleted");
        drop(accounts);
        let (reopened, _) = FileAccounts::open(&dir, Options::default()).expect("reopens");
        assert_eq!(reopened.revision().expect("read"), 4);
        let held = reopened.get("billing").expect("read").expect("held");
        assert_eq!(held.status, Status::Suspended);
        assert_eq!(held.created_at, 10);
        assert_eq!(held.updated_at, 20);
        assert_eq!(held.scopes.len(), 1);
        assert!(reopened.get("gone").expect("read").is_none());
        assert_eq!(
            reopened
                .by_access_key("pgak_AAAAAAAAAAAAAAAAAAAA")
                .expect("read")
                .expect("found")
                .0
                .name,
            "billing"
        );
    }

    #[test]
    fn what_the_store_would_never_hold_is_refused() {
        let dir = scratch("refused");
        let (accounts, _) = FileAccounts::open(&dir, Options::default()).expect("opens");
        for bad in ["", "Upper", "-dash", &"a".repeat(64), "sp ace"] {
            assert!(
                accounts
                    .create(None, Account::new(bad, "", Vec::new(), 1), "t", 1)
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
                    .create(None, Account::new("a", "", scopes, 1), "t", 1)
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
            accounts.create(None, three, "t", 1),
            Err(AccountsError::Conflict(_))
        ));
        let mut one = Account::new("one", "", Vec::new(), 1);
        one.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
        accounts.create(None, one, "t", 1).expect("written");
        let mut other = Account::new("other", "", Vec::new(), 1);
        other.keys = vec![key("pgak_AAAAAAAAAAAAAAAAAAAA")];
        assert!(matches!(
            accounts.create(None, other, "t", 1),
            Err(AccountsError::Conflict(_))
        ));
        accounts
            .create(None, Account::new(ADMIN, "", admin_scopes(), 1), "t", 1)
            .expect("the administrator");
        assert!(matches!(
            accounts.delete(None, ADMIN, &|_| Ok(()), "t", 2),
            Err(AccountsError::Conflict(_))
        ));
    }

    /// The file backend passes the contract's suite, each case on accounts of its own.
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let made = std::sync::atomic::AtomicUsize::new(0);
        let operating = crate::bench::Operating::new("accounts");
        super::super::suite::run(
            &|| {
                let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let dir = scratch(&format!("suite-{case}"));
                let (accounts, _) = FileAccounts::open(&dir, Options::default()).expect("opens");
                accounts
            },
            &|work| operating.run(super::super::DOMAIN, work),
        );
    }

    /// Two changes decided from one read of the account are both in the journal, in order.
    #[test]
    fn two_changes_of_one_account_are_both_kept_across_a_reopen() {
        let dir = scratch("both");
        let (accounts, _) = FileAccounts::open(&dir, Options::default()).expect("opens");
        accounts
            .create(None, Account::new("billing", "", Vec::new(), 1), "t", 1)
            .expect("written");
        accounts
            .update(
                None,
                "billing",
                &|held| {
                    let mut changed = held.clone();
                    changed.keys.push(key("pgak_AAAAAAAAAAAAAAAAAAAA"));
                    Ok(changed)
                },
                "t",
                2,
            )
            .expect("a key added");
        accounts
            .update(
                None,
                "billing",
                &|held| {
                    let mut changed = held.clone();
                    changed.description = "described".to_owned();
                    Ok(changed)
                },
                "t",
                3,
            )
            .expect("described");
        // A change that is refused appends no frame.
        assert!(
            accounts
                .update(
                    None,
                    "billing",
                    &|_| Err(AccountsError::Conflict("refused".to_owned())),
                    "t",
                    4
                )
                .is_err()
        );
        drop(accounts);
        let (reopened, _) = FileAccounts::open(&dir, Options::default()).expect("reopens");
        assert_eq!(reopened.revision().expect("read"), 3);
        let held = reopened.get("billing").expect("read").expect("held");
        assert_eq!(held.keys.len(), 1);
        assert_eq!(held.description, "described");
    }
}
