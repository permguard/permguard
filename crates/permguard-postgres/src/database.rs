// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The connections to PostgreSQL and the unit of work.
//!
//! # The unit of work
//!
//! [`Database::transaction`] runs a piece of work in one transaction at `SERIALIZABLE` isolation
//! (iteration 03, decision E25): what the work read cannot have changed under it when it commits,
//! so a check and the write it guards are one step without a lock of this process. A transaction
//! the database could not serialize with another, or chose as the victim of a deadlock, changed
//! nothing and is run again, a bounded number of times; the work is therefore a function that may
//! run more than once, and everything it does is inside the transaction.
//!
//! # Fail closed
//!
//! A database that does not answer is [`DbError::Unavailable`], and nothing is answered from a
//! copy in memory, because there is none (decision E28).

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use permguard_core::Metrics;
use permguard_core::metrics::{Metric, labels};
use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres::{Client, Row};

/// The units of work this process ended, by how: `committed`, `refused` by their own rule, or
/// `failed` when the database did.
pub const TRANSACTIONS: Metric = Metric::counter(
    "permguard_postgres_transactions_total",
    "Units of work on PostgreSQL, by outcome.",
);

/// How many times a unit of work was run again because the database could not serialize it.
pub const RETRIES: Metric = Metric::counter(
    "permguard_postgres_transaction_retries_total",
    "Units of work on PostgreSQL run again after a serialization failure or a deadlock.",
);

/// How many times a unit of work is run when the database could not serialize it, and the
/// longest it waits before running it again. The wait doubles from a millisecond and is spread
/// at random, so the transactions that collided do not collide again in step.
pub const ATTEMPTS: u32 = 16;
/// How many attempts a unit of work, or an operation, makes racing the others before it queues
/// (X113).
pub const OPTIMISTIC: u32 = 3;
/// The scope a unit of work that keeps losing queues on, across the instances.
const QUEUE: &str = "unit-of-work/queue";
const LONGEST_WAIT: Duration = Duration::from_millis(200);

/// How long the attempt `attempt`, counted from 1, waits before the next: between half of its
/// step and the whole of it.
pub fn pause(attempt: u32) -> Duration {
    let step = Duration::from_millis(1 << attempt.min(10)).min(LONGEST_WAIT);
    // Spread by the clock's low bits and the thread: enough to take colliding work out of step,
    // and nothing here needs a random number nobody could guess.
    let mut hasher = std::hash::DefaultHasher::new();
    std::hash::Hash::hash(&std::thread::current().id(), &mut hasher);
    std::hash::Hash::hash(&Instant::now(), &mut hasher);
    let spread = std::hash::Hasher::finish(&hasher) % 512;
    step / 2 + step.mul_f64(spread as f64 / 1024.0)
}

/// The connections one process keeps open at most, unless its configuration says otherwise.
pub const DEFAULT_POOL: usize = 16;

/// How long a connection is waited for, to be opened or to be free, before the database is said
/// unavailable.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(10);

/// How the connection to PostgreSQL is protected.
#[derive(Clone)]
pub enum Tls {
    /// No TLS: a database on the loopback interface of a development machine, and nowhere else.
    Disabled,
    /// TLS, the server's certificate verified against these roots and its name against the host.
    Verified(std::sync::Arc<rustls::RootCertStore>),
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "disabled",
            Self::Verified(_) => "verified",
        })
    }
}

/// Where the database is and how it is reached. Never printed: it holds the password.
#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: Option<String>,
    /// The schema the tables live in; the database's own search path when none is named.
    pub schema: Option<String>,
    pub tls: Tls,
    /// The connections kept open at most.
    pub pool: usize,
    /// How long a connection is waited for.
    pub wait: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("schema", &self.schema)
            .field("tls", &self.tls)
            .field("pool", &self.pool)
            .finish_non_exhaustive()
    }
}

/// The point a unit of work goes back to when work that joined it refuses.
const JOINED: &str = "permguard_joined";

/// Why the database did not do what it was asked.
#[derive(Debug)]
pub enum DbError {
    /// The database could not be reached, or did not answer in time, or failed: the caller's
    /// subsystem is not ready, and a retry is reasonable. A unit of work whose commit the
    /// database did not answer may have been kept all the same: a caller whose change cannot
    /// be made twice reads the state before it makes it again.
    Unavailable(String),
    /// The schema the database holds is newer than this build knows: the start is refused.
    SchemaNewer { found: i32, known: i32 },
    /// The database answered something this build does not read as it expects.
    Record(String),
    /// The work runs under a lease that is no longer this instance's (decision E27): it expired
    /// and another took it, so nothing is written under it.
    Fenced(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(detail) => write!(formatter, "PostgreSQL is not available: {detail}"),
            Self::SchemaNewer { found, known } => write!(
                formatter,
                "the database's schema is at version {found} and this build knows up to \
                 {known}: an older build never serves a newer schema"
            ),
            Self::Record(detail) => {
                write!(formatter, "PostgreSQL holds what does not read: {detail}")
            }
            Self::Fenced(lease) => write!(
                formatter,
                "the lease `{lease}` is no longer this instance's: nothing is written under it"
            ),
        }
    }
}

impl std::error::Error for DbError {}

/// Why a statement of a unit of work failed.
#[derive(Debug)]
pub enum SqlError {
    /// The database refused it or could not be reached.
    Db(postgres::Error),
    /// The unit's connection was given up: the unit was abandoned.
    Closed,
    /// A statement of the unit failed before, and the database keeps nothing of the unit: what
    /// that statement was answered.
    Failed {
        code: Option<SqlState>,
        detail: String,
    },
}

impl std::fmt::Display for SqlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The server's message, never the statement's parameters: a parameter may be a
            // secret.
            Self::Db(error) => match error.as_db_error() {
                Some(server) => {
                    write!(formatter, "{} ({})", server.message(), server.code().code())
                }
                None => write!(formatter, "{error}"),
            },
            Self::Closed => formatter.write_str("the unit of work was abandoned"),
            Self::Failed { detail, .. } => {
                write!(
                    formatter,
                    "a statement of the unit of work failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for SqlError {}

impl From<postgres::Error> for SqlError {
    fn from(error: postgres::Error) -> Self {
        Self::Db(error)
    }
}

impl SqlError {
    /// The SQLSTATE the database answered, when it answered one.
    pub fn code(&self) -> Option<&SqlState> {
        match self {
            Self::Db(error) => error.code(),
            Self::Closed => None,
            Self::Failed { code, .. } => code.as_ref(),
        }
    }
}

impl From<SqlError> for DbError {
    fn from(error: SqlError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

impl From<postgres::Error> for DbError {
    fn from(error: postgres::Error) -> Self {
        SqlError::Db(error).into()
    }
}

/// What ends a unit of work without its result: the database, or the work's own refusal.
#[derive(Debug)]
pub enum Failure<E> {
    /// The database failed. One it could not serialize is run again, not answered.
    Db(SqlError),
    /// The work refused, with its own reason: nothing it did is kept.
    Refused(E),
}

impl<E> From<SqlError> for Failure<E> {
    fn from(error: SqlError) -> Self {
        Self::Db(error)
    }
}

impl<E> From<postgres::Error> for Failure<E> {
    fn from(error: postgres::Error) -> Self {
        Self::Db(error.into())
    }
}

/// Whether the database rolled the transaction back for a reason that running it again cures:
/// it could not be serialized with another, or was the victim of a deadlock.
pub fn again(error: &SqlError) -> bool {
    matches!(
        error.code(),
        Some(code) if *code == SqlState::T_R_SERIALIZATION_FAILURE
            || *code == SqlState::T_R_DEADLOCK_DETECTED
    )
}

/// Runs `work`, which calls the synchronous client, where the client may block: on this thread
/// when it drives no asynchronous task, and on a thread of its own otherwise. The client blocks
/// on a runtime it owns, which a thread already inside a runtime may not do; the caller's thread
/// waits either way, as it waits on a file. `None` when no thread could be had for it, or the
/// work panicked.
fn apart<T: Send>(work: impl FnOnce() -> T + Send) -> Option<T> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Some(work());
    }
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("permguard-postgres".to_owned())
            .spawn_scoped(scope, work)
            .ok()?
            .join()
            .ok()
    })
}

/// How long a connection is silent before its first keepalive (WP-29.1).
const KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(10);
/// Between two unanswered keepalives.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// Unanswered keepalives after which the connection is closed.
const KEEPALIVE_RETRIES: u32 = 3;
/// How long what was sent may stay unacknowledged before the connection is closed.
const TCP_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What [`apart`] answers when the work was not run to its end.
fn no_thread() -> DbError {
    DbError::Unavailable("no thread could run the work on the database".to_owned())
}

thread_local! {
    /// The units of work open on this thread, the innermost last, each with the pool it is on.
    static OPEN: std::cell::RefCell<Vec<(usize, Arc<Unit>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

thread_local! {
    /// The leases the work of this thread runs under, each with the pool it is on: every unit of
    /// work the thread opens on that pool checks it first (decision E27).
    static FENCES: std::cell::RefCell<Vec<(usize, crate::lease::Lease)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// A lease made the fence of this thread's units of work until this is dropped
/// ([`Database::fenced`]).
pub struct Fenced {
    pool: usize,
}

impl Drop for Fenced {
    fn drop(&mut self) {
        FENCES.with(|fences| {
            let mut fences = fences.borrow_mut();
            if let Some(at) = fences.iter().rposition(|(pool, _)| *pool == self.pool) {
                fences.remove(at);
            }
        });
    }
}

/// A channel listened on ([`Database::listen`]); dropping it stops listening.
pub struct Listening {
    stopped: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A unit of work made the thread's own until this is dropped ([`Database::enter`]).
pub struct Entered {
    pool: usize,
}

impl Drop for Entered {
    fn drop(&mut self) {
        OPEN.with(|open| {
            let mut open = open.borrow_mut();
            if let Some(at) = open.iter().rposition(|(pool, _)| *pool == self.pool) {
                open.remove(at);
            }
        });
    }
}

/// The connections of one process to one database.
#[derive(Clone)]
pub struct Database {
    pool: Arc<Pool>,
}

struct Pool {
    config: Config,
    /// The connections that are open and free.
    free: Mutex<Vec<Client>>,
    /// How many connections are open, free or in use.
    open: Mutex<usize>,
    /// Told when a connection comes back or is closed.
    returned: Condvar,
    /// Where the numbers go; a handle that may hold nothing.
    metrics: Mutex<Metrics>,
    /// The queue of the work of this pool that waits for a scope held across units of work:
    /// one waits on the database at a time, so waiting holds no more than one connection.
    queued: Mutex<()>,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Database")
            .field("config", &self.pool.config)
            .finish_non_exhaustive()
    }
}

/// A connection taken from the pool, given back when dropped unless it was found broken or was
/// left inside a transaction.
struct Held {
    pool: Arc<Pool>,
    client: Option<Client>,
}

impl Drop for Held {
    fn drop(&mut self) {
        let Some(client) = self.client.take() else {
            return;
        };
        if client.is_closed() {
            // Closing a connection is the client's work too.
            let _ = apart(move || drop(client));
            *self
                .pool
                .open
                .lock()
                .unwrap_or_else(PoisonError::into_inner) -= 1;
        } else {
            self.pool
                .free
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(client);
        }
        self.pool.returned.notify_one();
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let free = std::mem::take(self.free.get_mut().unwrap_or_else(PoisonError::into_inner));
        let _ = apart(move || drop(free));
    }
}

/// How a transaction reads what others commit while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Isolation {
    Serializable,
    ReadCommitted,
}

/// One unit of work: a transaction that is open on a connection of its own, until it is
/// committed or dropped. Everything a store does of one operation it does through the unit it
/// is given; a unit dropped without a commit keeps nothing.
///
/// It is a value with no borrow in it, so the mutation engine can hand it to a domain write
/// inside the token the write takes (`Applying::unit`, iteration 03 decision E23).
pub struct Unit {
    held: Mutex<Held>,
    /// Whether the transaction was ended, by a commit or a rollback.
    ended: std::sync::atomic::AtomicBool,
    /// What the first statement that failed was answered. The database then keeps nothing of
    /// the transaction, and answers a `COMMIT` of it by undoing it without a word: the unit
    /// remembers, so that its commit says what happened.
    failed: Mutex<Option<(Option<SqlState>, String)>>,
}

impl std::fmt::Debug for Unit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Unit")
    }
}

impl Unit {
    fn begin(mut held: Held, isolation: Isolation) -> Result<Self, SqlError> {
        let statement = match isolation {
            Isolation::Serializable => "BEGIN ISOLATION LEVEL SERIALIZABLE",
            Isolation::ReadCommitted => "BEGIN ISOLATION LEVEL READ COMMITTED",
        };
        match held.client.as_mut() {
            Some(client) => apart(|| client.batch_execute(statement)).ok_or(SqlError::Closed)??,
            None => return Err(SqlError::Closed),
        }
        Ok(Self {
            held: Mutex::new(held),
            ended: std::sync::atomic::AtomicBool::new(false),
            failed: Mutex::new(None),
        })
    }

    /// Runs `ask` on the unit's connection.
    fn with<T>(
        &self,
        ask: impl FnOnce(&mut Client) -> Result<T, postgres::Error> + Send,
    ) -> Result<T, SqlError>
    where
        T: Send,
    {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let answered = match held.client.as_mut() {
            Some(client) => apart(|| ask(client))
                .ok_or(SqlError::Closed)
                .and_then(|answered| answered.map_err(SqlError::Db)),
            None => Err(SqlError::Closed),
        };
        if let Err(error) = &answered {
            let mut failed = self.failed.lock().unwrap_or_else(PoisonError::into_inner);
            if failed.is_none() {
                *failed = Some((error.code().cloned(), error.to_string()));
            }
        }
        answered
    }

    /// Runs a statement and answers how many rows it changed.
    pub fn execute(
        &self,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, SqlError> {
        self.with(|client| client.execute(statement, parameters))
    }

    /// Runs a query and answers its rows.
    pub fn query(
        &self,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, SqlError> {
        self.with(|client| client.query(statement, parameters))
    }

    /// Runs a query that answers one row or none.
    pub fn query_opt(
        &self,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, SqlError> {
        self.with(|client| client.query_opt(statement, parameters))
    }

    /// Runs a query that answers exactly one row.
    pub fn query_one(
        &self,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, SqlError> {
        self.with(|client| client.query_one(statement, parameters))
    }

    /// Runs statements that take no parameter, one after another.
    pub fn batch_execute(&self, statements: &str) -> Result<(), SqlError> {
        self.with(|client| client.batch_execute(statements))
    }

    /// Marks a point the unit can go back to with [`Unit::back_to`], keeping what came before.
    pub fn mark(&self, name: &str) -> Result<(), SqlError> {
        self.batch_execute(&format!("SAVEPOINT {name}"))
    }

    /// Undoes everything since [`Unit::mark`] of `name`; the unit goes on, a statement that
    /// failed since the mark undone with the rest. A unit the database could not serialize does
    /// not go on: nothing of it can be kept, whatever it goes back to.
    pub fn back_to(&self, name: &str) -> Result<(), SqlError> {
        let failed = self
            .failed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some((code, detail)) = failed {
            let failure = SqlError::Failed { code, detail };
            if again(&failure) {
                if let SqlError::Failed { code, detail } = &failure {
                    *self.failed.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some((code.clone(), detail.clone()));
                }
                return Err(failure);
            }
        }
        self.batch_execute(&format!("ROLLBACK TO SAVEPOINT {name}"))
    }

    /// What the first statement that failed in the unit was answered, when one did.
    pub fn failure(&self) -> Option<SqlError> {
        self.failed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .map(|(code, detail)| SqlError::Failed { code, detail })
    }

    /// Commits the unit: what it did is kept, all of it. Nothing is done through it afterwards.
    ///
    /// A unit one of whose statements failed is not committed: the database would undo it and
    /// say nothing, so the unit answers what that statement was answered.
    pub fn commit(&self) -> Result<(), SqlError> {
        if let Some(failure) = self.failure() {
            return Err(failure);
        }
        self.batch_execute("COMMIT")?;
        self.ended.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}

impl Drop for Unit {
    fn drop(&mut self) {
        if self.ended.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        // Not committed: nothing is kept. A connection that cannot be rolled back is closed,
        // never given back inside a transaction.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let rolled = held.client.as_mut().is_some_and(|client| {
            apart(|| client.batch_execute("ROLLBACK").is_ok()).unwrap_or(false)
        });
        if !rolled && let Some(client) = held.client.take() {
            // Closed apart, and its place in the pool given back.
            let _ = apart(move || drop(client));
            *held
                .pool
                .open
                .lock()
                .unwrap_or_else(PoisonError::into_inner) -= 1;
            held.pool.returned.notify_one();
        }
    }
}

/// A scope held by [`Database::hold_queued`]: the scope first let go, then the queue's turn.
pub struct Queued<'a> {
    _hold: Hold,
    _turn: std::sync::MutexGuard<'a, ()>,
}

/// A named scope held on a connection of its own, for as long as the value lives: of the
/// holders of one scope, on any instance, one holds it at a time and the others wait. What the
/// holder reads and writes under it, it does on that connection, each statement kept when it
/// is answered. The scope and the statements share the connection, so a holder whose
/// connection went holds nothing and writes nothing: it cannot write under a scope it lost.
pub struct Hold {
    held: Mutex<Held>,
}

impl std::fmt::Debug for Hold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hold")
    }
}

impl Hold {
    fn with<T: Send>(
        &self,
        ask: impl FnOnce(&mut Client) -> Result<T, postgres::Error> + Send,
    ) -> Result<T, SqlError> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        match held.client.as_mut() {
            Some(client) => apart(|| ask(client))
                .ok_or(SqlError::Closed)
                .and_then(|answered| answered.map_err(SqlError::Db)),
            None => Err(SqlError::Closed),
        }
    }

    /// Runs a statement and answers how many rows it changed.
    pub fn execute(
        &self,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, SqlError> {
        self.with(|client| client.execute(statement, parameters))
    }

    /// Runs a query and answers its rows.
    pub fn query(
        &self,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, SqlError> {
        self.with(|client| client.query(statement, parameters))
    }

    /// Runs a query that answers one row or none.
    pub fn query_opt(
        &self,
        statement: &str,
        parameters: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, SqlError> {
        self.with(|client| client.query_opt(statement, parameters))
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        // The scope is let go. A connection that cannot say it let it go is closed, which lets
        // it go, and is never given back holding it.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let released = held.client.as_mut().is_some_and(|client| {
            apart(|| {
                client
                    .batch_execute("SELECT pg_advisory_unlock_all()")
                    .is_ok()
            })
            .unwrap_or(false)
        });
        if !released && let Some(client) = held.client.take() {
            let _ = apart(move || drop(client));
            *held
                .pool
                .open
                .lock()
                .unwrap_or_else(PoisonError::into_inner) -= 1;
            held.pool.returned.notify_one();
        }
    }
}

impl Database {
    /// The database `config` names, one connection opened to prove it answers.
    pub fn connect(config: Config) -> Result<Self, DbError> {
        if config.pool == 0 {
            return Err(DbError::Unavailable(
                "a pool of no connection serves nothing".to_owned(),
            ));
        }
        // A schema's name goes into the connection's options as it is: only a plain identifier.
        if let Some(schema) = &config.schema
            && !(schema.starts_with(|first: char| first.is_ascii_lowercase())
                && schema
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
        {
            return Err(DbError::Unavailable(format!(
                "`{schema}` is no schema name: lowercase letters, digits and `_`, a letter first"
            )));
        }
        let database = Self {
            pool: Arc::new(Pool {
                config,
                free: Mutex::new(Vec::new()),
                open: Mutex::new(0),
                returned: Condvar::new(),
                metrics: Mutex::new(Metrics::none()),
                queued: Mutex::new(()),
            }),
        };
        database.ready()?;
        Ok(database)
    }

    /// This database, counting its units of work in `metrics`.
    #[must_use]
    pub fn with_metrics(self, metrics: Metrics) -> Self {
        *self
            .pool
            .metrics
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = metrics;
        self
    }

    fn metrics(&self) -> Metrics {
        self.pool
            .metrics
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Counts a unit of work that ended `outcome`: `committed`, `refused` or `failed`.
    pub fn ended(&self, outcome: &str) {
        self.metrics()
            .count(&TRANSACTIONS, &[(labels::OUTCOME, outcome)]);
    }

    /// Counts a unit of work run again.
    pub fn retried(&self) {
        self.metrics().count(&RETRIES, &[]);
    }

    /// Opens one connection.
    fn open(&self) -> Result<Client, DbError> {
        let config = &self.pool.config;
        let mut settings = postgres::Config::new();
        settings
            .host(&config.host)
            .port(config.port)
            .dbname(&config.database)
            .user(&config.user)
            .application_name("permguard")
            .connect_timeout(config.wait)
            // A database the network no longer reaches is told within a bound, not by the
            // system's own TCP timeouts, minutes later: what was sent and not acknowledged in
            // TCP_USER_TIMEOUT, or a connection silent and unanswering to its keepalives, is
            // closed, and the unit of work on it fails (iteration 03, WP-29.1).
            .keepalives(true)
            .keepalives_idle(KEEPALIVE_IDLE)
            .keepalives_interval(KEEPALIVE_INTERVAL)
            .keepalives_retries(KEEPALIVE_RETRIES)
            .tcp_user_timeout(TCP_USER_TIMEOUT);
        if let Some(password) = &config.password {
            settings.password(password);
        }
        if let Some(schema) = &config.schema {
            settings.options(&format!("-c search_path={schema}"));
        }
        let client = apart(|| match &config.tls {
            Tls::Disabled => settings.connect(postgres::NoTls),
            Tls::Verified(roots) => {
                let tls = rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::clone(roots))
                    .with_no_client_auth();
                settings.connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
            }
        })
        .ok_or_else(no_thread)?;
        client.map_err(|error| DbError::Unavailable(format!("connecting: {error}")))
    }

    /// A connection: a free one, a new one while the pool has room, or the next given back.
    /// Listens on `channel` on a connection of its own, and hands `heard` each payload the
    /// database notifies on it, until the answer is dropped (iteration 03, WP-28.4). A lost
    /// connection is told to `lost` and opened again after a pause: what was notified meanwhile
    /// is not heard, so what listens holds nothing that only a notification would bring.
    pub fn listen(
        &self,
        channel: &str,
        heard: Box<dyn Fn(&str) + Send + Sync>,
        lost: Box<dyn Fn(&DbError) + Send + Sync>,
    ) -> Result<Listening, DbError> {
        if channel.is_empty()
            || !channel
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(DbError::Unavailable(format!(
                "`{channel}` is no channel name: lowercase letters, digits and `_`"
            )));
        }
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (database, channel, stopping) =
            (self.clone(), channel.to_owned(), Arc::clone(&stopped));
        let thread = std::thread::Builder::new()
            .name(format!("pg-listen-{channel}"))
            .spawn(move || {
                let stopped = || stopping.load(std::sync::atomic::Ordering::SeqCst);
                while !stopped() {
                    let listened = database.open().and_then(|mut client| {
                        client
                            .batch_execute(&format!("LISTEN {channel}"))
                            .map_err(|error| DbError::Unavailable(error.to_string()))?;
                        while !stopped() {
                            let mut notifications = client.notifications();
                            let mut waiting =
                                notifications.timeout_iter(std::time::Duration::from_millis(500));
                            while let Some(notification) =
                                postgres::fallible_iterator::FallibleIterator::next(&mut waiting)
                                    .map_err(|error| DbError::Unavailable(error.to_string()))?
                            {
                                heard(notification.payload());
                            }
                        }
                        Ok(())
                    });
                    if let Err(error) = listened {
                        lost(&error);
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            })
            .map_err(|error| DbError::Unavailable(format!("a listening thread: {error}")))?;
        Ok(Listening {
            stopped,
            thread: Some(thread),
        })
    }

    fn take(&self) -> Result<Held, DbError> {
        let pool = &self.pool;
        let deadline = Instant::now() + pool.config.wait;
        let held = |client| Held {
            pool: Arc::clone(pool),
            client: Some(client),
        };
        loop {
            if let Some(client) = pool
                .free
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop()
            {
                if client.is_closed() {
                    let _ = apart(move || drop(client));
                    *pool.open.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
                    continue;
                }
                return Ok(held(client));
            }
            let mut open = pool.open.lock().unwrap_or_else(PoisonError::into_inner);
            if *open < pool.config.pool {
                *open += 1;
                drop(open);
                return match self.open() {
                    Ok(client) => Ok(held(client)),
                    Err(error) => {
                        *pool.open.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
                        pool.returned.notify_one();
                        Err(error)
                    }
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(DbError::Unavailable(format!(
                    "every one of the {} connections stayed in use for {:?}",
                    pool.config.pool, pool.config.wait
                )));
            }
            let _ = pool
                .returned
                .wait_timeout(open, left)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Whether the database answers now: what readiness asks.
    pub fn ready(&self) -> Result<(), DbError> {
        let mut held = self.take()?;
        match held.client.as_mut() {
            Some(client) => {
                apart(|| client.simple_query("SELECT 1")).ok_or_else(no_thread)??;
                Ok(())
            }
            None => Err(DbError::Unavailable("no connection".to_owned())),
        }
    }

    /// Opens one `SERIALIZABLE` unit of work for a caller that ends it itself: the mutation
    /// engine, which commits the unit a domain wrote in.
    pub fn begin(&self) -> Result<Arc<Unit>, DbError> {
        let unit = Arc::new(Unit::begin(self.take()?, Isolation::Serializable)?);
        self.fence(&unit)?;
        Ok(unit)
    }

    /// Opens one `READ COMMITTED` unit of work for a caller that ends it itself: a subsystem's
    /// gate, whose holder waits for the one before it and then reads what that one committed.
    pub fn begin_read_committed(&self) -> Result<Arc<Unit>, DbError> {
        let unit = Arc::new(Unit::begin(self.take()?, Isolation::ReadCommitted)?);
        self.fence(&unit)?;
        Ok(unit)
    }

    /// Makes `lease` the fence of every unit of work this thread opens on this database until
    /// the answer is dropped (decision E27): each checks, first, that the lease is still this
    /// holding, and keeps it so until it ends, so a unit commits only while the lease was held.
    /// What a single job does on its own thread is written under its lease, or not at all.
    #[must_use]
    pub fn fenced(&self, lease: crate::lease::Lease) -> Fenced {
        let pool = self.identity();
        FENCES.with(|fences| fences.borrow_mut().push((pool, lease)));
        Fenced { pool }
    }

    /// Checks, in `unit`, the lease this thread's work runs under on this database, if any.
    fn fence(&self, unit: &Unit) -> Result<(), DbError> {
        let pool = self.identity();
        let Some(lease) = FENCES.with(|fences| {
            fences
                .borrow()
                .iter()
                .rev()
                .find(|(of, _)| *of == pool)
                .map(|(_, lease)| lease.clone())
        }) else {
            return Ok(());
        };
        match crate::lease::held(unit, &lease, ()) {
            Ok(()) => Ok(()),
            Err(Failure::Refused(())) => Err(DbError::Fenced(lease.name)),
            Err(Failure::Db(error)) => Err(error.into()),
        }
    }

    /// Takes the scope `scope` on a connection of its own and holds it until the answer is
    /// dropped, waiting for the holder before it: for work that spans more than one unit of
    /// work and must be one holder's at a time, on whatever instance.
    pub fn hold(&self, scope: &str) -> Result<Hold, DbError> {
        let hold = Hold {
            held: Mutex::new(self.take()?),
        };
        hold.execute(
            "SELECT pg_advisory_lock(hashtextextended($1, 0))",
            &[&scope],
        )?;
        Ok(hold)
    }

    /// [`Database::hold`], taken in this pool's queue: of the work of this pool that waits for a
    /// scope, one waits on the database at a time, holding one connection, and the others wait
    /// in the process, holding none. The answer holds the scope and the queue's turn.
    pub fn hold_queued(&self, scope: &str) -> Result<Queued<'_>, DbError> {
        let turn = self
            .pool
            .queued
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(Queued {
            _hold: self.hold(scope)?,
            _turn: turn,
        })
    }

    /// Whether this thread is inside a unit of work on this database.
    pub fn inside(&self) -> bool {
        self.entered().is_some()
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.pool) as usize
    }

    /// Makes `unit` this thread's unit of work on this database until the answer is dropped:
    /// everything a store of this database does on this thread meanwhile, a read or a change,
    /// it does inside `unit`. An operation's domain write thereby reads what it wrote, and
    /// every store it changes changes with it or not at all.
    #[must_use]
    pub fn enter(&self, unit: &Arc<Unit>) -> Entered {
        let pool = self.identity();
        OPEN.with(|open| open.borrow_mut().push((pool, Arc::clone(unit))));
        Entered { pool }
    }

    /// The unit of work this thread is inside on this database, when it is inside one.
    fn entered(&self) -> Option<Arc<Unit>> {
        let pool = self.identity();
        OPEN.with(|open| {
            open.borrow()
                .iter()
                .rev()
                .find(|(of, _)| *of == pool)
                .map(|(_, unit)| Arc::clone(unit))
        })
    }

    /// Runs `work` in one `SERIALIZABLE` unit of work and commits it. A unit the database could
    /// not serialize changed nothing and is run again; `work` may therefore run more than once
    /// and does everything inside the unit it is given. A refusal of `work` keeps nothing and
    /// is answered as it is.
    pub fn transaction<T, E>(
        &self,
        work: impl Fn(&Unit) -> Result<T, Failure<E>>,
    ) -> Result<Result<T, E>, DbError> {
        self.run(Isolation::Serializable, None, &work)
    }

    /// Runs `work` in one unit of work that holds `scope` from its first statement to its end:
    /// of the units that take one scope, one runs at a time, and each sees what the ones before
    /// it committed. For a rule the rows do not state, and for work that many do at once on one
    /// row, where running it again and again would cost more than waiting in turn.
    ///
    /// The unit is at `READ COMMITTED`, not `SERIALIZABLE`: a serializable transaction reads
    /// from the moment of its first statement, which is the statement that waits for the scope,
    /// so it would decide on what was there before the holder it waited for committed.
    pub fn under_scope<T, E>(
        &self,
        scope: &str,
        work: impl Fn(&Unit) -> Result<T, Failure<E>>,
    ) -> Result<Result<T, E>, DbError> {
        self.run(Isolation::ReadCommitted, Some(scope), &work)
    }

    fn run<T, E>(
        &self,
        isolation: Isolation,
        scope: Option<&str>,
        work: &dyn Fn(&Unit) -> Result<T, Failure<E>>,
    ) -> Result<Result<T, E>, DbError> {
        // Inside a unit of work of this thread, the work is part of it: it is not committed
        // here and not run again. What it refuses keeps nothing, as when it runs alone: the
        // unit goes back to where the work began, and goes on from there.
        if let Some(unit) = self.entered() {
            if scope.is_some() {
                return Err(DbError::Unavailable(
                    "a scope is not taken inside a unit of work".to_owned(),
                ));
            }
            unit.mark(JOINED)?;
            return match work(&unit) {
                Ok(value) => {
                    unit.batch_execute(&format!("RELEASE SAVEPOINT {JOINED}"))?;
                    Ok(Ok(value))
                }
                Err(Failure::Refused(refusal)) => {
                    unit.back_to(JOINED)?;
                    Ok(Err(refusal))
                }
                Err(Failure::Db(error)) => Err(error.into()),
            };
        }
        {
            let mut last = None;
            // As an operation does (X113): a unit of work that keeps losing to others stops
            // racing them and queues, in this process first, then across the instances, for
            // the attempts it has left; a scoped one waits on its scope already.
            let mut queued = None;
            for attempt in 1..=ATTEMPTS {
                let attempted = (|| {
                    let unit = Arc::new(Unit::begin(
                        self.take().map_err(|error| Failure::Refused(Err(error)))?,
                        isolation,
                    )?);
                    if let Some(scope) = scope {
                        unit.execute(
                            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                            &[&scope],
                        )?;
                    }
                    // Under a lease, the unit is written only while the lease is this holding.
                    self.fence(&unit)
                        .map_err(|error| Failure::Refused(Err(error)))?;
                    // The unit is this thread's while the work runs: a store the work calls
                    // reads and writes in it, on its connection, and is kept or not with it.
                    let inside = self.enter(&unit);
                    let worked = work(&unit);
                    drop(inside);
                    let value = worked.map_err(|failure| match failure {
                        Failure::Db(error) => Failure::Db(error),
                        Failure::Refused(refusal) => Failure::Refused(Ok(refusal)),
                    })?;
                    unit.commit()?;
                    Ok::<T, Failure<Result<E, DbError>>>(value)
                })();
                match attempted {
                    Ok(value) => {
                        self.ended("committed");
                        return Ok(Ok(value));
                    }
                    Err(Failure::Refused(Ok(refusal))) => {
                        self.ended("refused");
                        return Ok(Err(refusal));
                    }
                    Err(Failure::Refused(Err(unavailable))) => {
                        self.ended("failed");
                        return Err(unavailable);
                    }
                    Err(Failure::Db(error)) if again(&error) => {
                        self.retried();
                        last = Some(error);
                        if scope.is_none() && attempt >= OPTIMISTIC && queued.is_none() {
                            queued = Some(self.hold_queued(QUEUE)?);
                        } else {
                            std::thread::sleep(pause(attempt));
                        }
                    }
                    Err(Failure::Db(error)) => {
                        self.ended("failed");
                        return Err(error.into());
                    }
                }
            }
            self.ended("failed");
            Err(DbError::Unavailable(format!(
                "a unit of work could not be serialized in {ATTEMPTS} attempts: {}",
                last.map_or_else(String::new, |error| error.to_string())
            )))
        }
    }

    /// Runs `work` as [`Self::transaction`] does, for work that has no refusal of its own.
    pub fn write<T>(&self, work: impl Fn(&Unit) -> Result<T, SqlError>) -> Result<T, DbError> {
        match self
            .transaction::<T, std::convert::Infallible>(|unit| work(unit).map_err(Failure::Db))?
        {
            Ok(value) => Ok(value),
            Err(never) => match never {},
        }
    }
}
