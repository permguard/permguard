// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a start completes of the tokens (`2-security/8` Stores).
//!
//! A change of an account that also changes its tokens writes the account first and the tokens
//! second, in two stores. A crash between the two leaves the account changed and its tokens as
//! they were, and recovery of the mutation journal finds the change applied. What the tokens
//! must be follows from the accounts alone, so a start reads the accounts and completes it,
//! before the Authority Plane serves:
//!
//! | The accounts say                                    | Every live token of it is |
//! | --------------------------------------------------- | ------------------------- |
//! | the account is not held                             | `INVALID`                 |
//! | the access key it was obtained with is not held     | `INVALID`                 |
//! | it carries a scope the account's no longer grant    | `INVALID`                 |
//! | the account is suspended, and the token is `VALID`  | `SUSPENDED`               |
//! | the account is active, and the token is `SUSPENDED` | `INVALID`                 |
//!
//! Each row is what the change itself writes, so on tokens that are as their accounts say the
//! pass changes nothing, and running it twice is running it once.
//!
//! One change reaches its tokens only here: `authority admin-key`, run with the server stopped,
//! removes `admin`'s oldest key to make room and opens the accounts alone, so the tokens that
//! key obtained end at the next start (decision E18 of iteration 03).
//!
//! The pass reads the accounts, then writes the tokens: it is right while nothing else changes
//! either, which is so at a start, before the plane serves. It is not run while the plane
//! serves, where an account made or a key added after its read would look gone to it.

use std::collections::BTreeMap;

use crate::accounts::{Account, AccountStore, Status};
use crate::authority::granted_within;
use crate::tokens::{IssuedToken, TokenStore, status};

/// Who the transitions a start writes are made by.
pub const BY: &str = "authority";

/// What a start changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Completed {
    /// The tokens made `INVALID`.
    pub invalidated: usize,
    /// The tokens made `SUSPENDED`.
    pub suspended: usize,
}

impl Completed {
    /// Whether anything was left to complete.
    pub fn is_empty(&self) -> bool {
        self.invalidated == 0 && self.suspended == 0
    }
}

/// Completes the tokens from the accounts at `now`. A store that does not answer completes
/// nothing, and the caller does not serve.
pub fn complete_tokens(
    accounts: &dyn AccountStore,
    tokens: &dyn TokenStore,
    now: u64,
) -> Result<Completed, String> {
    let held: BTreeMap<String, Account> = accounts
        .list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|account| (account.name.clone(), account))
        .collect();
    let revoked = |token: &IssuedToken| match held.get(&token.account) {
        None => true,
        Some(account) => {
            account.key(&token.access_key).is_none()
                || !granted_within(&token.scopes, &account.scopes)
                || (account.status == Status::Active && token.status == status::SUSPENDED)
        }
    };
    let invalidated = tokens
        .set_status(None, &revoked, status::INVALID, BY, now)
        .map_err(|error| error.to_string())?;
    let suspended = |token: &IssuedToken| {
        token.status == status::VALID
            && held
                .get(&token.account)
                .is_some_and(|account| account.status == Status::Suspended)
    };
    let suspended = tokens
        .set_status(None, &suspended, status::SUSPENDED, BY, now)
        .map_err(|error| error.to_string())?;
    Ok(Completed {
        invalidated,
        suspended,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use permguard_core::authz::{Selector, TokenScope};
    use permguard_host::storage::Dir;
    use permguard_host::storage::journal::Options;

    use super::*;
    use crate::accounts::AccessKey;
    use crate::accounts::files::FileAccounts;
    use crate::tokens::TokenDraft;
    use crate::tokens::files::FileTokens;

    const NOW: u64 = 1_800_000_000;
    const FIRST: &str = "pgak_AAAAAAAAAAAAAAAAAAAA";
    const SECOND: &str = "pgak_BBBBBBBBBBBBBBBBBBBB";

    fn stores(tag: &str) -> (Arc<FileAccounts>, Arc<FileTokens>) {
        let root = std::env::temp_dir().join(format!(
            "pg-authority-completion-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        let dir = Dir::open(&root).expect("a directory");
        let (accounts, _) = FileAccounts::open(&dir, Options::default()).expect("opens");
        let (tokens, _) = FileTokens::open(&dir, Options::default()).expect("opens");
        (accounts, tokens)
    }

    fn scope(operation: &str, selector: &str) -> TokenScope {
        TokenScope {
            operations: std::iter::once(operation.to_owned()).collect(),
            selector: Selector::parse(selector).expect("a selector"),
        }
    }

    fn key(id: &str) -> AccessKey {
        AccessKey {
            access_key: id.to_owned(),
            secret_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned(),
            created_at: NOW,
            expires_at: None,
        }
    }

    /// An account with two keys and two scopes, and one token of each key, the second carrying
    /// only the second scope.
    fn billing(accounts: &FileAccounts, tokens: &FileTokens) -> (IssuedToken, IssuedToken) {
        let evaluate = scope("decision.evaluate", "plane/data/*");
        let submit = scope("event.submit", "plane/data/*");
        let mut account = Account::new("billing", "", vec![evaluate.clone(), submit.clone()], NOW);
        account.keys = vec![key(FIRST), key(SECOND)];
        accounts.create(None, account, "t", NOW).expect("written");
        let issue = |access_key: &str, scopes: Vec<TokenScope>| {
            tokens
                .issue(
                    TokenDraft {
                        account: "billing".to_owned(),
                        access_key: access_key.to_owned(),
                        scopes,
                        expires_at: NOW + 3_600,
                    },
                    NOW,
                )
                .expect("issued")
        };
        (
            issue(FIRST, vec![evaluate, submit.clone()]),
            issue(SECOND, vec![submit]),
        )
    }

    fn status_of(tokens: &FileTokens, token: &IssuedToken) -> u8 {
        tokens
            .token(&token.jti)
            .expect("read")
            .expect("held")
            .status
    }

    fn change(accounts: &FileAccounts, change: &dyn Fn(&mut Account)) {
        accounts
            .update(
                None,
                "billing",
                &|held| {
                    let mut changed = held.clone();
                    change(&mut changed);
                    Ok(changed)
                },
                "t",
                NOW + 1,
            )
            .expect("changed");
    }

    #[test]
    fn tokens_that_are_as_their_accounts_say_are_left() {
        let (accounts, tokens) = stores("clean");
        let (first, second) = billing(&accounts, &tokens);
        let before = tokens.revision().expect("read");
        let completed = complete_tokens(&*accounts, &*tokens, NOW + 2).expect("completed");
        assert!(completed.is_empty(), "{completed:?}");
        assert_eq!(tokens.revision().expect("read"), before);
        assert_eq!(status_of(&tokens, &first), status::VALID);
        assert_eq!(status_of(&tokens, &second), status::VALID);
    }

    /// The account was deleted and the process died before its tokens were revoked.
    #[test]
    fn a_deleted_accounts_tokens_are_invalid() {
        let (accounts, tokens) = stores("deleted");
        let (first, second) = billing(&accounts, &tokens);
        accounts
            .delete(None, "billing", &|_| Ok(()), "t", NOW + 1)
            .expect("deleted");
        let completed = complete_tokens(&*accounts, &*tokens, NOW + 2).expect("completed");
        assert_eq!(
            completed,
            Completed {
                invalidated: 2,
                suspended: 0
            }
        );
        assert_eq!(status_of(&tokens, &first), status::INVALID);
        assert_eq!(status_of(&tokens, &second), status::INVALID);
        // Once is enough.
        assert!(
            complete_tokens(&*accounts, &*tokens, NOW + 3)
                .expect("completed")
                .is_empty()
        );
    }

    /// The account was suspended, then resumed, each time without its tokens following.
    #[test]
    fn a_suspension_and_a_resumption_reach_the_tokens() {
        let (accounts, tokens) = stores("suspended");
        let (first, second) = billing(&accounts, &tokens);
        change(&accounts, &|account| account.status = Status::Suspended);
        let completed = complete_tokens(&*accounts, &*tokens, NOW + 2).expect("completed");
        assert_eq!(
            completed,
            Completed {
                invalidated: 0,
                suspended: 2
            }
        );
        assert_eq!(status_of(&tokens, &first), status::SUSPENDED);
        assert_eq!(status_of(&tokens, &second), status::SUSPENDED);

        // A resumed account obtains new tokens; those it held when suspended end for good.
        change(&accounts, &|account| account.status = Status::Active);
        let completed = complete_tokens(&*accounts, &*tokens, NOW + 3).expect("completed");
        assert_eq!(
            completed,
            Completed {
                invalidated: 2,
                suspended: 0
            }
        );
        assert_eq!(status_of(&tokens, &first), status::INVALID);
        assert_eq!(status_of(&tokens, &second), status::INVALID);
    }

    /// A key was deleted: the tokens it obtained end, the other key's stay.
    #[test]
    fn a_deleted_keys_tokens_are_invalid_and_no_others() {
        let (accounts, tokens) = stores("key");
        let (first, second) = billing(&accounts, &tokens);
        change(&accounts, &|account| {
            account.keys.retain(|key| key.access_key != FIRST);
        });
        let completed = complete_tokens(&*accounts, &*tokens, NOW + 2).expect("completed");
        assert_eq!(
            completed,
            Completed {
                invalidated: 1,
                suspended: 0
            }
        );
        assert_eq!(status_of(&tokens, &first), status::INVALID);
        assert_eq!(status_of(&tokens, &second), status::VALID);
    }

    /// The scopes were narrowed: a token holding what they no longer grant ends, one within
    /// them stays.
    #[test]
    fn a_narrowing_ends_the_tokens_that_hold_more() {
        let (accounts, tokens) = stores("scopes");
        let (first, second) = billing(&accounts, &tokens);
        change(&accounts, &|account| {
            account.scopes = vec![scope("event.submit", "plane/data/*")];
        });
        let completed = complete_tokens(&*accounts, &*tokens, NOW + 2).expect("completed");
        assert_eq!(
            completed,
            Completed {
                invalidated: 1,
                suspended: 0
            }
        );
        assert_eq!(status_of(&tokens, &first), status::INVALID);
        assert_eq!(status_of(&tokens, &second), status::VALID);
    }

    /// `authority admin-key` removed `admin`'s oldest key offline, the tokens untouched: the
    /// next start ends the tokens that key obtained (decision E18).
    #[test]
    fn a_key_removed_offline_ends_its_tokens_at_the_next_start() {
        let (accounts, tokens) = stores("offline");
        let scopes = crate::accounts::admin_scopes();
        let mut admin = Account::new(crate::accounts::ADMIN, "", scopes.clone(), NOW);
        admin.keys = vec![key(FIRST), key(SECOND)];
        accounts.create(None, admin, "t", NOW).expect("written");
        let issue = |access_key: &str| {
            tokens
                .issue(
                    TokenDraft {
                        account: crate::accounts::ADMIN.to_owned(),
                        access_key: access_key.to_owned(),
                        scopes: scopes.clone(),
                        expires_at: NOW + 3_600,
                    },
                    NOW,
                )
                .expect("issued")
        };
        let (oldest, kept) = (issue(FIRST), issue(SECOND));
        let root = std::env::temp_dir().join(format!(
            "pg-authority-completion-offline-out-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        crate::admin::offline_key(&*accounts, &root, &root.join("new.key"), NOW + 1)
            .expect("a key made offline");
        let held = accounts
            .get(crate::accounts::ADMIN)
            .expect("read")
            .expect("held");
        assert!(held.key(FIRST).is_none(), "the oldest key went");
        assert_eq!(
            status_of(&tokens, &oldest),
            status::VALID,
            "untouched offline"
        );

        let completed = complete_tokens(&*accounts, &*tokens, NOW + 2).expect("completed");
        assert_eq!(
            completed,
            Completed {
                invalidated: 1,
                suspended: 0
            }
        );
        assert_eq!(status_of(&tokens, &oldest), status::INVALID);
        assert_eq!(status_of(&tokens, &kept), status::VALID);
    }
}
