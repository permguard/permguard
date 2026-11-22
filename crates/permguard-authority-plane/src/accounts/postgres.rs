// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`AccountStore`]: a row an account, its access keys and its scopes
//! in tables beside it.
//!
//! | Rule of the contract                        | Kept by                                               |
//! | ------------------------------------------- | ----------------------------------------------------- |
//! | an access key names one key of one account  | the key's primary key                                 |
//! | a change reads the account it replaces      | the read and the write in one serializable transaction |
//! | an operation changes the accounts once      | the operation's primary key                           |
//! | the revision rises by one with every change | one row, raised in the transaction of the change      |
//! | a deleted account's keys name nothing       | the keys' and the scopes' foreign key                 |
//!
//! Every change of an account raises the same row, so two changes that meet are applied one
//! after the other: it is what the contract's revision asks, a count of every change.
//!
//! Nothing is kept in memory. Inside an operation of the mutation engine every call is made in
//! the operation's transaction; outside one, a change is a transaction of its own.

use permguard_core::authz::{Selector, TokenScope};
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::Applying;
use permguard_postgres::{Database, DbError, Failure, SqlError, Unit};

use super::{
    ADMIN, AccessKey, Account, AccountStore, AccountsError, MAX_ACCOUNTS, Status, validate,
};

/// The accounts of one database.
#[derive(Debug, Clone)]
pub struct PostgresAccounts {
    database: Database,
}

impl From<DbError> for AccountsError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

fn held_wrong(what: &str) -> Failure<AccountsError> {
    Failure::Refused(AccountsError::Unavailable(format!(
        "the accounts hold {what} that does not read"
    )))
}

fn seconds(value: i64, what: &str) -> Result<u64, Failure<AccountsError>> {
    u64::try_from(value).map_err(|_| held_wrong(what))
}

fn kept(value: u64) -> Result<i64, Failure<AccountsError>> {
    i64::try_from(value).map_err(|_| {
        Failure::Refused(AccountsError::Invalid(
            "a time or a revision past what the store keeps".to_owned(),
        ))
    })
}

/// The account `name` as the unit sees it, its scopes and keys in their order.
fn read(unit: &Unit, name: &str) -> Result<Option<Account>, Failure<AccountsError>> {
    let Some(row) = unit.query_opt(
        "SELECT description, status, created_at, updated_at, revision
         FROM permguard_authority_accounts WHERE name = $1",
        &[&name],
    )?
    else {
        return Ok(None);
    };
    let status = match row.get::<_, String>(1).as_str() {
        "active" => Status::Active,
        "suspended" => Status::Suspended,
        _ => return Err(held_wrong("a status")),
    };
    let mut scopes = Vec::new();
    for scope in unit.query(
        "SELECT operations, selector FROM permguard_authority_scopes
         WHERE account = $1 ORDER BY position",
        &[&name],
    )? {
        scopes.push(TokenScope {
            operations: scope.get::<_, Vec<String>>(0).into_iter().collect(),
            selector: Selector::parse(&scope.get::<_, String>(1))
                .map_err(|_| held_wrong("a selector"))?,
        });
    }
    let mut keys = Vec::new();
    for key in unit.query(
        "SELECT access_key, secret_hash, created_at, expires_at
         FROM permguard_authority_access_keys WHERE account = $1 ORDER BY position",
        &[&name],
    )? {
        keys.push(AccessKey {
            access_key: key.get(0),
            secret_hash: key.get(1),
            created_at: seconds(key.get(2), "a key's time")?,
            expires_at: key
                .get::<_, Option<i64>>(3)
                .map(|at| seconds(at, "a key's expiry"))
                .transpose()?,
        });
    }
    Ok(Some(Account {
        name: name.to_owned(),
        description: row.get(0),
        status,
        scopes,
        keys,
        created_at: seconds(row.get(2), "a time")?,
        updated_at: seconds(row.get(3), "a time")?,
        revision: seconds(row.get(4), "a revision")?,
    }))
}

/// Refuses `account` an access key another account holds.
fn key_of_another(unit: &Unit, account: &Account) -> Result<(), Failure<AccountsError>> {
    for key in &account.keys {
        if unit
            .query_opt(
                "SELECT 1 FROM permguard_authority_access_keys
                 WHERE access_key = $1 AND account <> $2",
                &[&key.access_key, &account.name],
            )?
            .is_some()
        {
            return Err(Failure::Refused(AccountsError::Conflict(format!(
                "the access key {} belongs to another account",
                key.access_key
            ))));
        }
    }
    Ok(())
}

/// Writes one change: the account `name` as `account`, or its deletion, at the next revision.
fn write(
    unit: &Unit,
    applying: Option<&Applying<'_>>,
    name: &str,
    account: Option<Account>,
    by: &str,
    now: u64,
) -> Result<Option<Account>, Failure<AccountsError>> {
    let operation = applying.map(|applying| applying.operation_id());
    if let Some(operation) = &operation
        && unit
            .query_opt(
                "SELECT 1 FROM permguard_authority_account_operations WHERE operation_id = $1",
                &[&operation.as_bytes().as_slice()],
            )?
            .is_some()
    {
        return Err(Failure::Refused(AccountsError::Conflict(
            "this operation already changed an account".to_owned(),
        )));
    }
    let revision: i64 = unit
        .query_one(
            "UPDATE permguard_authority_revisions SET revision = revision + 1
             WHERE store = 'accounts' RETURNING revision",
            &[],
        )?
        .get(0);
    let account = account.map(|account| Account {
        updated_at: now,
        revision: revision.unsigned_abs(),
        ..account
    });
    match &account {
        Some(account) => {
            unit.execute(
                "INSERT INTO permguard_authority_accounts AS held
                     (name, description, status, created_at, updated_at, revision, updated_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (name) DO UPDATE SET
                     description = EXCLUDED.description, status = EXCLUDED.status,
                     updated_at = EXCLUDED.updated_at, revision = EXCLUDED.revision,
                     updated_by = EXCLUDED.updated_by",
                &[
                    &account.name,
                    &account.description,
                    &account.status.as_str(),
                    &kept(account.created_at)?,
                    &kept(account.updated_at)?,
                    &revision,
                    &by,
                ],
            )?;
            unit.execute(
                "DELETE FROM permguard_authority_scopes WHERE account = $1",
                &[&account.name],
            )?;
            unit.execute(
                "DELETE FROM permguard_authority_access_keys WHERE account = $1",
                &[&account.name],
            )?;
            for (position, scope) in account.scopes.iter().enumerate() {
                unit.execute(
                    "INSERT INTO permguard_authority_scopes (account, position, operations, selector)
                     VALUES ($1, $2, $3, $4)",
                    &[
                        &account.name,
                        &(position as i32),
                        &scope.operations.iter().cloned().collect::<Vec<String>>(),
                        &scope.selector.to_string(),
                    ],
                )?;
            }
            for (position, key) in account.keys.iter().enumerate() {
                unit.execute(
                    "INSERT INTO permguard_authority_access_keys
                         (access_key, account, position, secret_hash, created_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &key.access_key,
                        &account.name,
                        &(position as i32),
                        &key.secret_hash,
                        &kept(key.created_at)?,
                        &key.expires_at.map(kept).transpose()?,
                    ],
                )?;
            }
        }
        None => {
            unit.execute(
                "DELETE FROM permguard_authority_accounts WHERE name = $1",
                &[&name],
            )?;
        }
    }
    if let Some(operation) = &operation {
        unit.execute(
            "INSERT INTO permguard_authority_account_operations (operation_id, revision, account)
             VALUES ($1, $2, $3)",
            &[&operation.as_bytes().as_slice(), &revision, &name],
        )?;
    }
    Ok(account)
}

impl PostgresAccounts {
    /// The accounts of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    /// Runs `work` in the operation's transaction when this thread is inside one, and in a
    /// transaction of its own otherwise.
    fn within<T>(
        &self,
        work: impl Fn(&Unit) -> Result<T, Failure<AccountsError>>,
    ) -> Result<T, AccountsError> {
        self.database.transaction(work)?
    }

    fn asked<T>(&self, ask: impl Fn(&Unit) -> Result<T, SqlError>) -> Result<T, AccountsError> {
        Ok(self.database.write(ask)?)
    }
}

impl AccountStore for PostgresAccounts {
    fn revision(&self) -> Result<u64, AccountsError> {
        let revision: i64 = self.asked(|unit| {
            Ok(unit
                .query_one(
                    "SELECT revision FROM permguard_authority_revisions WHERE store = 'accounts'",
                    &[],
                )?
                .get(0))
        })?;
        Ok(revision.unsigned_abs())
    }

    fn get(&self, name: &str) -> Result<Option<Account>, AccountsError> {
        self.within(|unit| read(unit, name))
    }

    fn list(&self) -> Result<Vec<Account>, AccountsError> {
        self.within(|unit| {
            let mut accounts = Vec::new();
            for row in unit.query(
                "SELECT name FROM permguard_authority_accounts ORDER BY name",
                &[],
            )? {
                let name: String = row.get(0);
                accounts.extend(read(unit, &name)?);
            }
            Ok(accounts)
        })
    }

    fn count(&self) -> Result<usize, AccountsError> {
        let count: i64 = self.asked(|unit| {
            Ok(unit
                .query_one("SELECT count(*) FROM permguard_authority_accounts", &[])?
                .get(0))
        })?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    fn by_access_key(
        &self,
        access_key: &str,
    ) -> Result<Option<(Account, AccessKey)>, AccountsError> {
        self.within(|unit| {
            let Some(row) = unit.query_opt(
                "SELECT account FROM permguard_authority_access_keys WHERE access_key = $1",
                &[&access_key],
            )?
            else {
                return Ok(None);
            };
            let name: String = row.get(0);
            Ok(read(unit, &name)?.and_then(|account| {
                let key = account.key(access_key).cloned()?;
                Some((account, key))
            }))
        })
    }

    fn operation(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<(u64, String)>, AccountsError> {
        let held = self.asked(|unit| {
            unit.query_opt(
                "SELECT revision, account FROM permguard_authority_account_operations
                 WHERE operation_id = $1",
                &[&operation_id.as_bytes().as_slice()],
            )
        })?;
        Ok(held.map(|row| (row.get::<_, i64>(0).unsigned_abs(), row.get(1))))
    }

    fn create(
        &self,
        applying: Option<&Applying<'_>>,
        account: Account,
        by: &str,
        now: u64,
    ) -> Result<Account, AccountsError> {
        validate(&account, now)?;
        self.within(|unit| {
            if read(unit, &account.name)?.is_some() {
                return Err(Failure::Refused(AccountsError::Conflict(format!(
                    "the service account `{}` exists",
                    account.name
                ))));
            }
            let held: i64 = unit
                .query_one("SELECT count(*) FROM permguard_authority_accounts", &[])?
                .get(0);
            if usize::try_from(held).unwrap_or(usize::MAX) >= MAX_ACCOUNTS {
                return Err(Failure::Refused(AccountsError::Conflict(format!(
                    "the Authority Plane holds at most {MAX_ACCOUNTS} service accounts"
                ))));
            }
            key_of_another(unit, &account)?;
            write(
                unit,
                applying,
                &account.name,
                Some(account.clone()),
                by,
                now,
            )?
            .ok_or_else(|| Failure::Refused(AccountsError::NotFound(account.name.clone())))
        })
    }

    fn update(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        change: &dyn Fn(&Account) -> Result<Account, AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<Account, AccountsError> {
        // The account `change` is given and the one its answer replaces are read and written in
        // one serializable transaction: nothing changes the account between the two.
        self.within(|unit| {
            let held = read(unit, name)?.ok_or_else(|| {
                Failure::Refused(AccountsError::NotFound(format!(
                    "no service account `{name}`"
                )))
            })?;
            let changed = Account {
                name: held.name.clone(),
                created_at: held.created_at,
                ..change(&held).map_err(Failure::Refused)?
            };
            validate(&changed, now).map_err(Failure::Refused)?;
            key_of_another(unit, &changed)?;
            write(unit, applying, name, Some(changed), by, now)?
                .ok_or_else(|| Failure::Refused(AccountsError::NotFound(name.to_owned())))
        })
    }

    fn delete(
        &self,
        applying: Option<&Applying<'_>>,
        name: &str,
        allow: &dyn Fn(&Account) -> Result<(), AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<(), AccountsError> {
        self.within(|unit| {
            let account = read(unit, name)?.ok_or_else(|| {
                Failure::Refused(AccountsError::NotFound(format!(
                    "no service account `{name}`"
                )))
            })?;
            if account.name == ADMIN {
                return Err(Failure::Refused(AccountsError::Conflict(
                    "`admin` is never deleted: there is always one account that can repair the \
                     others"
                        .to_owned(),
                )));
            }
            allow(&account).map_err(Failure::Refused)?;
            write(unit, applying, name, None, by, now).map(|_| ())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use permguard_postgres::testing::server;

    use super::*;
    use crate::on_postgres::Cases;

    /// The PostgreSQL backend passes the contract's suite, the one the file backend passes: each
    /// case on a schema of its own, every change of an operation inside a transaction of the
    /// mutation engine of that database.
    #[test]
    fn the_accounts_keep_their_contract_on_postgresql() {
        let Some(server) = server("the_accounts_keep_their_contract_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        crate::accounts::suite::run(&|| Arc::new(PostgresAccounts::new(cases.next())), &|work| {
            cases.operate(crate::accounts::DOMAIN, work)
        });
    }
}
