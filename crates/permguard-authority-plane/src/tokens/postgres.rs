// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`TokenStore`]: a row a token, a row a list, the scopes of a token
//! beside it.
//!
//! | Rule of the contract                              | Kept by                                        |
//! | ------------------------------------------------- | ---------------------------------------------- |
//! | an entry is never drawn again in its list         | the unique key of a list's entries             |
//! | one list is open                                  | a unique index on the open list                |
//! | `INVALID` is terminal                             | the statement that changes a status            |
//! | a list's tokens are forgotten with it             | the tokens' foreign key                        |
//! | the revision rises with every change              | one row, raised in the transaction of a change |
//!
//! A list is not kept as its bits: it is the status of the tokens that drew its entries, read
//! when the list is asked for. Every change raises the tokens' revision row, so the changes of
//! the tokens are applied one after another, in the order the revision gives them: a list's
//! `changed_at` is never behind a change another transaction committed first.
//!
//! Nothing is kept in memory. A token is issued inside the unit of work its caller holds the
//! subsystem in (decision E26), and a status is changed inside the operation's transaction.

use std::collections::BTreeMap;

use permguard_core::authz::{Selector, TokenScope};
use permguard_host::authz::access_tokens::CLOCK_SKEW;
use permguard_host::identity::record::{uuid_text, uuid_v7};
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::Applying;
use permguard_objects::status_list::{ENTRIES, StatusList};
use permguard_postgres::{Database, DbError, Failure, SqlError, Unit};

use super::files::random;
use super::{BITS, IssuedToken, ListView, OPEN_UNTIL, TokenDraft, TokenError, TokenStore, status};

/// The tokens of one database.
#[derive(Debug, Clone)]
pub struct PostgresTokens {
    database: Database,
}

impl From<DbError> for TokenError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

fn held_wrong(what: &str) -> Failure<TokenError> {
    Failure::Refused(TokenError::Unavailable(format!(
        "the tokens hold {what} that does not read"
    )))
}

fn id(bytes: Vec<u8>, what: &str) -> Result<[u8; 16], Failure<TokenError>> {
    bytes.try_into().map_err(|_| held_wrong(what))
}

fn unsigned(value: i64, what: &str) -> Result<u64, Failure<TokenError>> {
    u64::try_from(value).map_err(|_| held_wrong(what))
}

fn kept(value: u64) -> Result<i64, Failure<TokenError>> {
    i64::try_from(value).map_err(|_| {
        Failure::Refused(TokenError::Invalid(
            "a time past what the store keeps".to_owned(),
        ))
    })
}

/// Raises the tokens' revision by one and answers it: the change it counts is this unit's.
fn raise(unit: &Unit) -> Result<i64, SqlError> {
    Ok(unit
        .query_one(
            "UPDATE permguard_authority_revisions SET revision = revision + 1
             WHERE store = 'tokens' RETURNING revision",
            &[],
        )?
        .get(0))
}

/// The tokens `condition` selects, newest first, each with its scopes in their order.
fn tokens(
    unit: &Unit,
    condition: &str,
    parameters: &[&(dyn permguard_postgres::ToSql + Sync)],
) -> Result<Vec<IssuedToken>, Failure<TokenError>> {
    let rows = unit.query(
        &format!(
            "SELECT t.jti, t.list_id, t.entry, t.account, t.access_key, t.issued_at,
                    t.expires_at, t.status, s.operations, s.selector
             FROM permguard_authority_tokens t
             LEFT JOIN permguard_authority_token_scopes s ON s.jti = t.jti
             WHERE {condition}
             ORDER BY t.jti DESC, s.position"
        ),
        parameters,
    )?;
    let mut found: Vec<IssuedToken> = Vec::new();
    for row in rows {
        let jti = id(row.get(0), "a token's id")?;
        if found.last().is_none_or(|last| last.jti != jti) {
            found.push(IssuedToken {
                jti,
                list_id: id(row.get(1), "a list's id")?,
                index: u64::try_from(row.get::<_, i32>(2)).map_err(|_| held_wrong("an entry"))?,
                account: row.get(3),
                access_key: row.get(4),
                scopes: Vec::new(),
                issued_at: unsigned(row.get(5), "a time")?,
                expires_at: unsigned(row.get(6), "a time")?,
                status: u8::try_from(row.get::<_, i16>(7)).map_err(|_| held_wrong("a status"))?,
            });
        }
        if let (Some(operations), Some(selector), Some(token)) = (
            row.get::<_, Option<Vec<String>>>(8),
            row.get::<_, Option<String>>(9),
            found.last_mut(),
        ) {
            token.scopes.push(TokenScope {
                operations: operations.into_iter().collect(),
                selector: Selector::parse(&selector).map_err(|_| held_wrong("a selector"))?,
            });
        }
    }
    Ok(found)
}

impl PostgresTokens {
    /// The tokens of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    /// Runs `work` in the unit of work this thread is inside, and in a transaction of its own
    /// otherwise.
    fn within<T>(
        &self,
        work: impl Fn(&Unit) -> Result<T, Failure<TokenError>>,
    ) -> Result<T, TokenError> {
        self.database.transaction(work)?
    }
}

impl TokenStore for PostgresTokens {
    fn revision(&self) -> Result<u64, TokenError> {
        let revision: i64 = self.database.write(|unit| {
            Ok(unit
                .query_one(
                    "SELECT revision FROM permguard_authority_revisions WHERE store = 'tokens'",
                    &[],
                )?
                .get(0))
        })?;
        Ok(revision.unsigned_abs())
    }

    fn issue(&self, draft: TokenDraft, now: u64) -> Result<IssuedToken, TokenError> {
        if draft.expires_at <= now {
            return Err(TokenError::Invalid(
                "a token expires after it is issued".to_owned(),
            ));
        }
        if draft.scopes.is_empty() {
            return Err(TokenError::Invalid("a token carries a scope".to_owned()));
        }
        self.within(|unit| {
            // The revision row first: every change of the tokens takes it, so this one reads the
            // open list as the change before it left it.
            let mut revision = raise(unit)?;
            let open = unit.query_opt(
                "SELECT list_id FROM permguard_authority_lists WHERE open AND drawn < $1",
                &[&(OPEN_UNTIL as i32)],
            )?;
            let list_id = match open {
                Some(row) => id(row.get(0), "a list's id")?,
                None => {
                    let list_id = uuid_v7(
                        now.saturating_mul(1000),
                        random().map_err(Failure::Refused)?,
                    );
                    unit.execute(
                        "UPDATE permguard_authority_lists SET open = false WHERE open",
                        &[],
                    )?;
                    unit.execute(
                        "INSERT INTO permguard_authority_lists
                             (list_id, open, drawn, latest_expiry, changed_at)
                         VALUES ($1, true, 0, 0, $2)",
                        &[&list_id.as_slice(), &revision],
                    )?;
                    // Opening the list is a change of its own, as the token is.
                    revision = raise(unit)?;
                    list_id
                }
            };
            let _ = revision;
            let jti = uuid_v7(
                now.saturating_mul(1000),
                random().map_err(Failure::Refused)?,
            );
            // Drawn at random among the free entries; a bound of draws keeps a failing random
            // source from spinning. An entry already drawn in the list writes nothing.
            let mut drawn = None;
            for _ in 0..256 {
                let candidate =
                    (u32::from_le_bytes(random().map_err(Failure::Refused)?) as usize) % ENTRIES;
                let written = unit.execute(
                    "INSERT INTO permguard_authority_tokens
                         (jti, list_id, entry, account, access_key, issued_at, expires_at, status)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, 0)
                     ON CONFLICT (list_id, entry) DO NOTHING",
                    &[
                        &jti.as_slice(),
                        &list_id.as_slice(),
                        &(candidate as i32),
                        &draft.account,
                        &draft.access_key,
                        &kept(now)?,
                        &kept(draft.expires_at)?,
                    ],
                )?;
                if written == 1 {
                    drawn = Some(candidate);
                    break;
                }
            }
            let index = drawn.ok_or_else(|| {
                Failure::Refused(TokenError::Invalid(
                    "no free entry was drawn in 256 tries".to_owned(),
                ))
            })?;
            unit.execute(
                "UPDATE permguard_authority_lists
                 SET drawn = drawn + 1, latest_expiry = GREATEST(latest_expiry, $2)
                 WHERE list_id = $1",
                &[&list_id.as_slice(), &kept(draft.expires_at)?],
            )?;
            for (position, scope) in draft.scopes.iter().enumerate() {
                unit.execute(
                    "INSERT INTO permguard_authority_token_scopes
                         (jti, position, operations, selector)
                     VALUES ($1, $2, $3, $4)",
                    &[
                        &jti.as_slice(),
                        &(position as i32),
                        &scope.operations.iter().cloned().collect::<Vec<String>>(),
                        &scope.selector.to_string(),
                    ],
                )?;
            }
            Ok(IssuedToken {
                jti,
                list_id,
                index: index as u64,
                account: draft.account.clone(),
                access_key: draft.access_key.clone(),
                scopes: draft.scopes.clone(),
                issued_at: now,
                expires_at: draft.expires_at,
                status: status::VALID,
            })
        })
    }

    fn set_status(
        &self,
        applying: Option<&Applying<'_>>,
        matches: &dyn Fn(&IssuedToken) -> bool,
        value: u8,
        _by: &str,
        now: u64,
    ) -> Result<usize, TokenError> {
        if !matches!(value, status::VALID | status::INVALID | status::SUSPENDED) {
            return Err(TokenError::Invalid(format!(
                "{value} is not a token status"
            )));
        }
        self.within(|unit| {
            // The revision row first, raised or not: what this change reads of the tokens is
            // what the change before it left.
            unit.execute(
                "SELECT revision FROM permguard_authority_revisions
                 WHERE store = 'tokens' FOR UPDATE",
                &[],
            )?;
            // A Plane accepts a token a clock skew past its `exp`: until then it can be
            // revoked, and its list kept.
            let candidates = tokens(
                unit,
                "t.expires_at + $1 > $2 AND t.status <> 1 AND t.status <> $3",
                &[&kept(CLOCK_SKEW)?, &kept(now)?, &i16::from(value)],
            )?;
            let mut changed = 0usize;
            // Oldest first, as the file backend's journal orders them.
            for token in candidates.iter().rev().filter(|token| matches(token)) {
                let revision = raise(unit)?;
                unit.execute(
                    "UPDATE permguard_authority_tokens SET status = $2
                     WHERE jti = $1 AND status <> 1",
                    &[&token.jti.as_slice(), &i16::from(value)],
                )?;
                unit.execute(
                    "UPDATE permguard_authority_lists SET changed_at = $2 WHERE list_id = $1",
                    &[&token.list_id.as_slice(), &revision],
                )?;
                // One operation names its first transition: what recovery observes.
                if changed == 0
                    && let Some(applying) = applying
                {
                    unit.execute(
                        "INSERT INTO permguard_authority_token_operations
                             (operation_id, revision, named)
                         VALUES ($1, $2, $3)",
                        &[
                            &applying.operation_id().as_bytes().as_slice(),
                            &revision,
                            &uuid_text(&token.jti),
                        ],
                    )?;
                }
                changed += 1;
            }
            Ok(changed)
        })
    }

    fn retire_expired(&self, _by: &str, now: u64) -> Result<usize, TokenError> {
        self.within(|unit| {
            let expired = unit.query(
                "SELECT list_id FROM permguard_authority_lists
                 WHERE NOT open AND latest_expiry + $1 < $2 ORDER BY list_id",
                &[&kept(CLOCK_SKEW)?, &kept(now)?],
            )?;
            for row in &expired {
                raise(unit)?;
                unit.execute(
                    "DELETE FROM permguard_authority_lists WHERE list_id = $1",
                    &[&row.get::<_, Vec<u8>>(0)],
                )?;
            }
            Ok(expired.len())
        })
    }

    fn token(&self, jti: &[u8; 16]) -> Result<Option<IssuedToken>, TokenError> {
        self.within(|unit| Ok(tokens(unit, "t.jti = $1", &[&jti.as_slice()])?.pop()))
    }

    fn live_tokens(&self, now: u64) -> Result<Vec<IssuedToken>, TokenError> {
        self.within(|unit| tokens(unit, "t.expires_at > $1", &[&kept(now)?]))
    }

    fn last_used(&self, access_key: &str) -> Result<Option<u64>, TokenError> {
        let last: Option<i64> = self.database.write(|unit| {
            Ok(unit
                .query_one(
                    "SELECT max(issued_at) FROM permguard_authority_tokens WHERE access_key = $1",
                    &[&access_key],
                )?
                .get(0))
        })?;
        Ok(last.map(i64::unsigned_abs))
    }

    fn list(&self, list_id: &[u8; 16]) -> Result<Option<ListView>, TokenError> {
        self.within(|unit| {
            let Some(row) = unit.query_opt(
                "SELECT changed_at FROM permguard_authority_lists WHERE list_id = $1",
                &[&list_id.as_slice()],
            )?
            else {
                return Ok(None);
            };
            let mut list = StatusList::new(BITS, ENTRIES)
                .map_err(|error| Failure::Refused(TokenError::Invalid(error.to_string())))?;
            for entry in unit.query(
                "SELECT entry, status FROM permguard_authority_tokens
                 WHERE list_id = $1 AND status <> 0",
                &[&list_id.as_slice()],
            )? {
                let index =
                    usize::try_from(entry.get::<_, i32>(0)).map_err(|_| held_wrong("an entry"))?;
                let value =
                    u8::try_from(entry.get::<_, i16>(1)).map_err(|_| held_wrong("a status"))?;
                list.set(index, value).map_err(|_| held_wrong("an entry"))?;
            }
            Ok(Some(ListView {
                list_id: *list_id,
                list,
                changed_at: unsigned(row.get(0), "a revision")?,
            }))
        })
    }

    fn list_ids(&self) -> Result<Vec<[u8; 16]>, TokenError> {
        self.within(|unit| {
            unit.query(
                "SELECT list_id FROM permguard_authority_lists ORDER BY list_id",
                &[],
            )?
            .into_iter()
            .map(|row| id(row.get(0), "a list's id"))
            .collect()
        })
    }

    fn changed_at(&self, list_id: &[u8; 16]) -> Result<Option<u64>, TokenError> {
        let changed: Option<i64> = self
            .database
            .write(|unit| {
                unit.query_opt(
                    "SELECT changed_at FROM permguard_authority_lists WHERE list_id = $1",
                    &[&list_id.as_slice()],
                )
            })?
            .map(|row| row.get(0));
        Ok(changed.map(i64::unsigned_abs))
    }

    fn operation(&self, operation_id: &OperationId) -> Result<Option<(u64, String)>, TokenError> {
        let held = self.database.write(|unit| {
            unit.query_opt(
                "SELECT revision, named FROM permguard_authority_token_operations
                 WHERE operation_id = $1",
                &[&operation_id.as_bytes().as_slice()],
            )
        })?;
        Ok(held.map(|row| (row.get::<_, i64>(0).unsigned_abs(), row.get(1))))
    }
}

/// The marks' store beside it: one row a list.
#[derive(Debug, Clone)]
pub struct PostgresMarks {
    database: Database,
}

impl PostgresMarks {
    /// The marks of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}

impl crate::marks::MarkStore for PostgresMarks {
    fn held(&self) -> BTreeMap<[u8; 16], u64> {
        // None when the store does not answer, as the contract says of marks that do not read.
        self.database
            .write(|unit| unit.query("SELECT list_id, mark FROM permguard_authority_marks", &[]))
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|row| {
                        let list: [u8; 16] = row.get::<_, Vec<u8>>(0).try_into().ok()?;
                        Some((list, u64::try_from(row.get::<_, i64>(1)).ok()?))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn keep(&self, marks: &BTreeMap<[u8; 16], u64>) -> Result<(), String> {
        self.database
            .write(|unit| {
                // The marks held are replaced whole, and a mark only rises: of two instances
                // that sign one list, the higher `iat` is the one kept.
                let named: Vec<&[u8]> = marks.keys().map(<[u8; 16]>::as_slice).collect();
                unit.execute(
                    "DELETE FROM permguard_authority_marks WHERE NOT (list_id = ANY($1))",
                    &[&named],
                )?;
                for (list, mark) in marks {
                    unit.execute(
                        "INSERT INTO permguard_authority_marks AS held (list_id, mark)
                         VALUES ($1, $2)
                         ON CONFLICT (list_id) DO UPDATE SET mark = EXCLUDED.mark
                         WHERE held.mark < EXCLUDED.mark",
                        &[&list.as_slice(), &i64::try_from(*mark).unwrap_or(i64::MAX)],
                    )?;
                }
                Ok(())
            })
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use permguard_postgres::testing::{Cases, server};

    use super::*;
    use crate::marks::MarkStore as _;

    /// The PostgreSQL backend passes the contract's suite, the one the file backend passes.
    #[test]
    fn the_tokens_keep_their_contract_on_postgresql() {
        let Some(server) = server("the_tokens_keep_their_contract_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        crate::tokens::suite::run(&|| Arc::new(PostgresTokens::new(cases.next())), &|work| {
            cases.operate(crate::tokens::DOMAIN, work)
        });
    }

    /// E26 between instances: a token is issued in the unit of work its caller holds the
    /// subsystem in, and a suspension ends the account's tokens in its own operation, under the
    /// same subsystem. Whichever instance each reached and however they met, no token of a
    /// suspended account is left valid.
    #[test]
    fn a_token_issued_while_its_account_is_suspended_is_never_left_valid_on_postgresql() {
        use std::sync::Barrier;

        use permguard_core::authz::{Selector, operations};
        use permguard_host::composition::MutationHandle;
        use permguard_host::operations::journal::Initiator;
        use permguard_host::operations::mutation::{Applied, Begin, Failure, MutationError};
        use permguard_postgres::mutations::PostgresMutations;
        use permguard_postgres::testing::{config, scratch};

        use crate::accounts::postgres::PostgresAccounts;
        use crate::accounts::{Account, AccountStore as _, Status};

        let test =
            "a_token_issued_while_its_account_is_suspended_is_never_left_valid_on_postgresql";
        let Some(server) = server(test) else {
            return;
        };
        let case = scratch(&server);
        // Two instances: connections, stores and an engine each, over one database.
        let instance = || {
            let database = Database::connect(config(&server, Some(case.schema.clone()), 4))
                .expect("an instance connects");
            (
                PostgresAccounts::new(database.clone()),
                PostgresTokens::new(database.clone()),
                MutationHandle::over(
                    Arc::new(PostgresMutations::new(database)),
                    crate::accounts::DOMAIN,
                )
                .in_subsystem(crate::PLANE),
            )
        };
        let (issuer, suspender) = (instance(), instance());
        let scope = TokenScope {
            operations: [operations::DECISION_EVALUATE.to_owned()].into(),
            selector: Selector::parse("plane/data/*").expect("a selector"),
        };
        const ROUNDS: usize = 6;
        const NOW: u64 = 1_800_000_000;
        for round in 0..ROUNDS {
            let name = format!("billing-{round}");
            issuer
                .0
                .create(
                    None,
                    Account::new(&name, "", vec![scope.clone()], NOW),
                    "t",
                    NOW,
                )
                .expect("an account");
            let barrier = Barrier::new(2);
            std::thread::scope(|threads| {
                // One instance issues a token, the account read and the token recorded as one
                // step under the subsystem.
                threads.spawn(|| {
                    barrier.wait();
                    let (accounts, tokens, handle) = &issuer;
                    let _ = handle.consistent(|| {
                        let account = accounts.get(&name).expect("read").expect("held");
                        // Long enough for the suspension to end between the read and the
                        // issue, were the subsystem not held from the one to the other.
                        std::thread::sleep(std::time::Duration::from_millis(40));
                        if account.status == Status::Active {
                            tokens
                                .issue(
                                    TokenDraft {
                                        account: name.clone(),
                                        access_key: "pgak_AAAAAAAAAAAAAAAAAAAA".to_owned(),
                                        scopes: vec![scope.clone()],
                                        expires_at: NOW + 600,
                                    },
                                    NOW,
                                )
                                .expect("issued");
                        }
                    });
                });
                // The other suspends the account and ends its tokens, in one operation, run
                // again while the database could not serialize it.
                threads.spawn(|| {
                    barrier.wait();
                    let (accounts, tokens, handle) = &suspender;
                    loop {
                        let ended = handle.run_checked::<(), String>(
                            Begin {
                                domain: crate::accounts::DOMAIN,
                                operation: "authority.account.suspend",
                                action: "authority.account.suspended",
                                initiator: Initiator::System("test".to_owned()),
                                request: None,
                                target: None,
                            },
                            || Ok(()),
                            |applying| {
                                accounts
                                    .update(
                                        Some(applying),
                                        &name,
                                        &|held| {
                                            Ok(Account {
                                                status: Status::Suspended,
                                                ..held.clone()
                                            })
                                        },
                                        "t",
                                        NOW,
                                    )
                                    .map_err(|error| Failure::Indeterminate(error.to_string()))?;
                                tokens
                                    .set_status(
                                        None,
                                        &|token| token.account == name,
                                        status::INVALID,
                                        "t",
                                        NOW,
                                    )
                                    .map_err(|error| Failure::Indeterminate(error.to_string()))?;
                                Ok(Applied {
                                    revision: 0,
                                    target: None,
                                    value: (),
                                })
                            },
                        );
                        match ended {
                            Ok(_) => break,
                            // Nothing was kept: the same change again.
                            Err(
                                MutationError::Unavailable(_) | MutationError::Indeterminate(_),
                            ) => {}
                            Err(other) => {
                                panic!("round {round}: the suspension answered {other:?}")
                            }
                        }
                    }
                });
            });
            let account = issuer.0.get(&name).expect("read").expect("held");
            assert_eq!(account.status, Status::Suspended, "round {round}");
            let left: Vec<_> = issuer
                .1
                .live_tokens(NOW)
                .expect("read")
                .into_iter()
                .filter(|token| token.account == name && token.status == status::VALID)
                .collect();
            assert!(
                left.is_empty(),
                "round {round}: a token of a suspended account is still valid: {left:?}"
            );
        }
    }

    /// The marks are kept whole and only rise: a list no longer signed is forgotten, and of two
    /// instances that sign one list the higher `iat` is the one kept, whichever kept it last.
    #[test]
    fn the_marks_are_kept_whole_and_only_rise_on_postgresql() {
        let Some(server) = server("the_marks_are_kept_whole_and_only_rise_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        let (one, other) = (
            PostgresMarks::new(database.clone()),
            PostgresMarks::new(database),
        );
        assert!(one.held().is_empty());
        one.keep(&BTreeMap::from([([1; 16], 100), ([2; 16], 200)]))
            .expect("kept");
        assert_eq!(
            other.held(),
            BTreeMap::from([([1; 16], 100), ([2; 16], 200)])
        );
        // Another instance, behind on one list and ahead on another, with one list gone.
        other
            .keep(&BTreeMap::from([([1; 16], 90), ([3; 16], 300)]))
            .expect("kept");
        assert_eq!(
            one.held(),
            BTreeMap::from([([1; 16], 100), ([3; 16], 300)]),
            "a mark never goes back, and a list no longer signed is forgotten"
        );
    }
}
