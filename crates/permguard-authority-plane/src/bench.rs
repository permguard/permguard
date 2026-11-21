// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A whole Authority in a test: its stores on a scratch volume, the mutation engine, a ring
//! that signs, and an actor every operation admits (iteration 03, decision E30).
//!
//! What it proves is what no store proves alone: that an account's change and the tokens it
//! ends are one step for every token being issued (decision E26).

#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Actor, ActorContext, Credential, Principal, Selector, TokenScope};
use permguard_core::keys::PublicSet;
use permguard_host::authz::Authorization;
use permguard_host::composition::MutationHandle;
use permguard_host::composition::{AUTHORITY_TOKENS, AccessTokenV1, Declaration, Host};
use permguard_host::operations::mutation::Mutations;
use permguard_host::storage::Dir;
use permguard_host::storage::journal::Options;
use permguard_host::storage::volume::Volume;
use permguard_host::time::TimeGuard;
use zeroize::Zeroizing;

use crate::accounts::files::FileAccounts;
use crate::accounts::{self, AccessKey, Account, AccountStore, Status};
use crate::authority::{Authority, CLIENT_CREDENTIALS, Change, Parts, TokenRefusal, TokenRequest};
use crate::completion::complete_tokens;
use crate::tokens::files::FileTokens;
use crate::tokens::{self, TokenStore, status};
use crate::{PLANE, access_keys};

type Ring = Arc<dyn permguard_core::KeyManager>;

/// A ring at its first epoch: what a signer reads of a key set.
struct EpochOne(Ring);

impl permguard_core::keys::Sign for EpochOne {
    fn active_key_id(&self) -> permguard_core::keys::Result<permguard_core::KeyId> {
        self.0.active_key_id()
    }
    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<permguard_core::Signature> {
        self.0.sign(payload)
    }
}

impl PublicSet for EpochOne {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<permguard_core::Jwk>> {
        self.0.public_keys()
    }
    fn key_set(&self) -> permguard_core::keys::Result<permguard_core::keys::KeySetView> {
        let keys = self.0.public_keys()?;
        let published = serde_json::to_vec(&permguard_core::JwkSet::new(keys))
            .map_err(|error| permguard_core::KeyError::backend(error.to_string()))?;
        Ok(permguard_core::keys::KeySetView {
            epoch: 1,
            digest: *permguard_objects::Digest::compute(&published).raw(),
            algorithm: "EdDSA",
        })
    }
}

impl permguard_core::KeyManager for EpochOne {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn maintain(&self) -> permguard_core::keys::Result<permguard_core::Maintenance> {
        self.0.maintain()
    }
}

/// The accounts as the Authority reads them, with one read a test may hold: the read a token's
/// issue makes of its account, so a test places a change of the account exactly between that
/// read and the token written from it.
#[derive(Debug)]
struct Pausing {
    inner: Arc<FileAccounts>,
    /// Whether the next read of an account is held.
    armed: AtomicBool,
    /// Set once the held read was made.
    reached: (Mutex<bool>, Condvar),
    /// Set to let the held read go on.
    released: (Mutex<bool>, Condvar),
}

impl Pausing {
    /// How long a held read waits to be let go before it goes on by itself: under the gate the
    /// change that would let it go waits for the issue, so the issue goes on alone.
    const HELD_FOR: std::time::Duration = std::time::Duration::from_millis(400);

    fn new(inner: Arc<FileAccounts>) -> Self {
        Self {
            inner,
            armed: AtomicBool::new(false),
            reached: (Mutex::new(false), Condvar::new()),
            released: (Mutex::new(false), Condvar::new()),
        }
    }

    /// Holds the next read of an account.
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Waits until the held read was made.
    fn wait_reached(&self) {
        let (lock, signal) = &self.reached;
        let mut reached = lock.lock().expect("lock");
        while !*reached {
            reached = signal.wait(reached).expect("lock");
        }
    }

    /// Lets the held read go on.
    fn release(&self) {
        let (lock, signal) = &self.released;
        *lock.lock().expect("lock") = true;
        signal.notify_all();
    }
}

impl AccountStore for Pausing {
    fn revision(&self) -> Result<u64, accounts::AccountsError> {
        self.inner.revision()
    }

    fn get(&self, name: &str) -> Result<Option<Account>, accounts::AccountsError> {
        let read = self.inner.get(name);
        if self.armed.swap(false, Ordering::SeqCst) {
            {
                let (lock, signal) = &self.reached;
                *lock.lock().expect("lock") = true;
                signal.notify_all();
            }
            let (lock, signal) = &self.released;
            let released = lock.lock().expect("lock");
            let _ = signal
                .wait_timeout_while(released, Self::HELD_FOR, |released| !*released)
                .expect("lock");
        }
        read
    }

    fn list(&self) -> Result<Vec<Account>, accounts::AccountsError> {
        self.inner.list()
    }

    fn count(&self) -> Result<usize, accounts::AccountsError> {
        self.inner.count()
    }

    fn by_access_key(
        &self,
        access_key: &str,
    ) -> Result<Option<(Account, AccessKey)>, accounts::AccountsError> {
        self.inner.by_access_key(access_key)
    }

    fn operation(
        &self,
        operation_id: &permguard_host::operations::journal::OperationId,
    ) -> Result<Option<(u64, String)>, accounts::AccountsError> {
        self.inner.operation(operation_id)
    }

    fn create(
        &self,
        applying: Option<&permguard_host::operations::mutation::Applying<'_>>,
        account: Account,
        by: &str,
        now: u64,
    ) -> Result<Account, accounts::AccountsError> {
        self.inner.create(applying, account, by, now)
    }

    fn update(
        &self,
        applying: Option<&permguard_host::operations::mutation::Applying<'_>>,
        name: &str,
        change: &dyn Fn(&Account) -> Result<Account, accounts::AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<Account, accounts::AccountsError> {
        self.inner.update(applying, name, change, by, now)
    }

    fn delete(
        &self,
        applying: Option<&permguard_host::operations::mutation::Applying<'_>>,
        name: &str,
        allow: &dyn Fn(&Account) -> Result<(), accounts::AccountsError>,
        by: &str,
        now: u64,
    ) -> Result<(), accounts::AccountsError> {
        self.inner.delete(applying, name, allow, by, now)
    }
}

/// The Authority and what a test reads behind it.
struct Bench {
    authority: Authority,
    accounts: Arc<Pausing>,
    tokens: Arc<FileTokens>,
    root: std::path::PathBuf,
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn bench(tag: &str) -> Bench {
    let root =
        std::env::temp_dir().join(format!("pg-authority-bench-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch");
    let volume = Volume::claim(&root.join("volume"), AssuranceProfile::Development)
        .expect("the volume is claimed");
    let engine = Arc::new(Mutations::open_offline(&volume, "bench").expect("the engine opens"));
    let plane = root.join("plane");
    std::fs::create_dir_all(&plane).expect("the plane's directory");
    let dir = Dir::open(&plane).expect("a directory");
    let (accounts, _) = FileAccounts::open(&dir, Options::default()).expect("accounts open");
    let accounts = Arc::new(Pausing::new(accounts));
    let (tokens, _) = FileTokens::open(&dir, Options::default()).expect("tokens open");

    let keys: Ring = Arc::new(permguard_std::keys::DirectoryKeyManager::new(
        root.join("keys"),
        permguard_std::keys::KeyPolicy {
            publish_ahead: std::time::Duration::ZERO,
            rotate_every: std::time::Duration::from_secs(3600),
            retain: std::time::Duration::from_secs(3600),
            verify_retain: std::time::Duration::from_secs(3600),
        },
    ));
    keys.maintain().expect("the ring publishes");
    keys.maintain().expect("the ring activates");
    let keys: Ring = Arc::new(EpochOne(keys));
    let signer = Host::builder()
        .ring(AUTHORITY_TOKENS, keys)
        .build()
        .register(Declaration::new(PLANE).signs::<AccessTokenV1>())
        .expect("the declaration registers")
        .signer::<AccessTokenV1>()
        .expect("a signer")
        .expect("the ring is composed");

    let authority = Authority::new(Parts {
        accounts: Arc::clone(&accounts) as Arc<dyn AccountStore>,
        registry: Arc::clone(&tokens) as Arc<dyn TokenStore>,
        tokens: Some(signer),
        lists: None,
        issuer: "https://authority.example:8443".to_owned(),
        audience: "permguard".to_owned(),
        profile: AssuranceProfile::Development,
        authorization: Arc::new(Authorization::permissive()),
        // As the plane composes it: both domains in one subsystem.
        mutations: Some(MutationHandle::new(engine, accounts::DOMAIN).in_subsystem(PLANE)),
        audit: None,
        trust: None,
        time: Arc::new(TimeGuard::system(std::time::Duration::from_secs(30))),
        marks: None,
    })
    .expect("the Authority is made");
    Bench {
        authority,
        accounts,
        tokens,
        root,
    }
}

fn operator() -> Actor {
    Actor::Authenticated(ActorContext::new(
        Principal::new("cert:sha256:ab").expect("a principal"),
        Credential::Certificate,
        None,
    ))
}

/// An account with one key, and the key's secret.
fn account_with_key(bench: &Bench, name: &str, now: u64) -> (String, Zeroizing<String>) {
    let access_key = access_keys::draw_access_key().expect("an access key");
    let secret = access_keys::draw_secret_key().expect("a secret");
    let mut account = Account::new(
        name,
        "",
        vec![TokenScope {
            operations: std::iter::once("decision.evaluate".to_owned()).collect(),
            selector: Selector::parse("plane/data/*").expect("a selector"),
        }],
        now,
    );
    account.keys = vec![AccessKey {
        access_key: access_key.clone(),
        secret_hash: access_keys::hash(&secret).expect("hashed"),
        created_at: now,
        expires_at: None,
    }];
    bench
        .accounts
        .create(None, account, "bench", now)
        .expect("the account is written");
    (access_key, secret)
}

fn request(access_key: &str, secret: &Zeroizing<String>) -> TokenRequest {
    TokenRequest {
        grant_type: CLIENT_CREDENTIALS.to_owned(),
        client_id: access_key.to_owned(),
        client_secret: secret.clone(),
        scope: None,
        requested_lifetime: None,
    }
}

fn change(at: usize) -> Change {
    Change {
        request_id: format!("bench-{at}"),
        expected_revision: None,
    }
}

/// The tokens of `account` that are neither expired nor ended, by status.
fn valid_tokens(bench: &Bench, account: &str) -> usize {
    bench
        .tokens
        .live_tokens(0)
        .expect("the tokens read")
        .iter()
        .filter(|token| token.account == account && token.status == status::VALID)
        .count()
}

/// The bench works: a token is issued, and a suspension ends it.
#[test]
fn the_bench_issues_a_token_and_a_suspension_suspends_it() {
    let bench = bench("works");
    let (access_key, secret) = account_with_key(&bench, "billing", 1);
    let issued = bench
        .authority
        .issue_token(&request(&access_key, &secret), "192.0.2.1")
        .expect("issued");
    assert_eq!(issued.account, "billing");
    assert_eq!(valid_tokens(&bench, "billing"), 1);

    let view = bench
        .authority
        .set_account_status(&operator(), "billing", true, change(0))
        .expect("suspended");
    assert_eq!(view.status, "suspended");
    assert_eq!(valid_tokens(&bench, "billing"), 0);
    assert!(matches!(
        bench
            .authority
            .issue_token(&request(&access_key, &secret), "192.0.2.1"),
        Err(TokenRefusal::InvalidClient)
    ));
    let held = bench.accounts.get("billing").expect("read").expect("held");
    assert_eq!(held.status, Status::Suspended);
    assert_eq!(tokens::DOMAIN, "authority.tokens");
}

/// A token's issue reads its account, and before the token is written the account is
/// suspended: the read is held, and the suspension is asked for while it is. Under the gate the
/// suspension waits for the issue, then suspends the token it wrote; without it the suspension
/// would answer first, find no token to suspend, and the issue would then write a valid token
/// of a suspended account from the account it read before. Either way the test ends the same
/// way when the Authority is right: the account suspended, no token of it valid, and nothing
/// for a start to complete.
#[test]
fn a_token_issued_across_a_suspension_does_not_stay_valid() {
    let bench = bench("gate");
    let (access_key, secret) = account_with_key(&bench, "billing", 1);

    std::thread::scope(|scope| {
        bench.accounts.arm();
        let issuing = scope.spawn(|| {
            bench
                .authority
                .issue_token(&request(&access_key, &secret), "192.0.2.1")
        });
        // The issue has read the account, active, and holds there.
        bench.accounts.wait_reached();
        bench
            .authority
            .set_account_status(&operator(), "billing", true, change(0))
            .expect("suspended");
        // Whatever the order was, the held read may go on now.
        bench.accounts.release();
        // The issue answers a token, or a refusal: both are right, what is checked is the state.
        let _ = issuing.join().expect("the issue ended");
    });

    let held = bench.accounts.get("billing").expect("read").expect("held");
    assert_eq!(held.status, Status::Suspended);
    assert_eq!(
        valid_tokens(&bench, "billing"),
        0,
        "a token issued from a read made before the suspension stayed valid"
    );
    let completed = complete_tokens(&*bench.accounts, &*bench.tokens, 2).expect("completed");
    assert!(
        completed.is_empty(),
        "left for a start to complete: {completed:?}"
    );
}
