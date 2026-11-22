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

use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use permguard_core::Metrics;
use permguard_core::metrics::{Metric, labels};
use postgres::error::SqlState;
use postgres::{Client, IsolationLevel, Transaction};

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
const ATTEMPTS: u32 = 16;
const LONGEST_WAIT: Duration = Duration::from_millis(200);

/// How long the attempt `attempt`, counted from 1, waits before the next: between half of its
/// step and the whole of it.
fn pause(attempt: u32) -> Duration {
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

/// Why the database did not do what it was asked.
#[derive(Debug)]
pub enum DbError {
    /// The database could not be reached, or did not answer in time, or failed: the caller's
    /// subsystem is not ready, and a retry is reasonable.
    Unavailable(String),
    /// The schema the database holds is newer than this build knows: the start is refused.
    SchemaNewer { found: i32, known: i32 },
    /// The database answered something this build does not read as it expects.
    Record(String),
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
        }
    }
}

impl std::error::Error for DbError {}

impl From<postgres::Error> for DbError {
    fn from(error: postgres::Error) -> Self {
        // The server's message, never the statement's parameters: a parameter may be a secret.
        match error.as_db_error() {
            Some(server) => {
                Self::Unavailable(format!("{} ({})", server.message(), server.code().code()))
            }
            None => Self::Unavailable(error.to_string()),
        }
    }
}

/// What ends a unit of work without its result: the database, or the work's own refusal.
#[derive(Debug)]
pub enum Failure<E> {
    /// The database failed. One it could not serialize is run again, not answered.
    Db(postgres::Error),
    /// The work refused, with its own reason: nothing it did is kept.
    Refused(E),
}

impl<E> From<postgres::Error> for Failure<E> {
    fn from(error: postgres::Error) -> Self {
        Self::Db(error)
    }
}

/// Whether the database rolled the transaction back for a reason that running it again cures:
/// it could not be serialized with another, or was the victim of a deadlock.
fn again(error: &postgres::Error) -> bool {
    matches!(
        error.code(),
        Some(code) if *code == SqlState::T_R_SERIALIZATION_FAILURE
            || *code == SqlState::T_R_DEADLOCK_DETECTED
    )
}

/// The connections of one process to one database.
pub struct Database {
    config: Config,
    /// The connections that are open and free.
    free: Mutex<Vec<Client>>,
    /// How many connections are open, free or in use.
    open: Mutex<usize>,
    /// Told when a connection comes back or is closed.
    returned: Condvar,
    /// Where the numbers go; a handle that may hold nothing.
    metrics: Metrics,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Database")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// A connection taken from the pool, given back when dropped unless it was found broken.
struct Held<'a> {
    database: &'a Database,
    client: Option<Client>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let kept = self.client.take().filter(|client| !client.is_closed());
        if let Some(client) = kept {
            self.database
                .free
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(client);
        } else {
            *self
                .database
                .open
                .lock()
                .unwrap_or_else(PoisonError::into_inner) -= 1;
        }
        self.database.returned.notify_one();
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
            config,
            free: Mutex::new(Vec::new()),
            open: Mutex::new(0),
            returned: Condvar::new(),
            metrics: Metrics::none(),
        };
        database.ready()?;
        Ok(database)
    }

    /// This database, counting its units of work in `metrics`.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    fn ended(&self, outcome: &str) {
        self.metrics
            .count(&TRANSACTIONS, &[(labels::OUTCOME, outcome)]);
    }

    /// Runs `work` on a thread that drives no asynchronous task, and answers what it answered.
    /// The synchronous client blocks on a runtime of its own, which a thread already inside a
    /// runtime may not do; the caller's thread waits, as it does on a file.
    fn apart<T: Send>(work: impl FnOnce() -> T + Send) -> Result<T, DbError> {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("permguard-postgres".to_owned())
                .spawn_scoped(scope, work)
                .map_err(|error| DbError::Unavailable(format!("no thread for the work: {error}")))?
                .join()
                .map_err(|_| DbError::Unavailable("the work on the database panicked".to_owned()))
        })
    }

    /// Opens one connection.
    fn open(&self) -> Result<Client, DbError> {
        let mut settings = postgres::Config::new();
        settings
            .host(&self.config.host)
            .port(self.config.port)
            .dbname(&self.config.database)
            .user(&self.config.user)
            .application_name("permguard")
            .connect_timeout(self.config.wait);
        if let Some(password) = &self.config.password {
            settings.password(password);
        }
        if let Some(schema) = &self.config.schema {
            settings.options(&format!("-c search_path={schema}"));
        }
        let client = match &self.config.tls {
            Tls::Disabled => settings.connect(postgres::NoTls),
            Tls::Verified(roots) => {
                let tls = rustls::ClientConfig::builder()
                    .with_root_certificates(std::sync::Arc::clone(roots))
                    .with_no_client_auth();
                settings.connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
            }
        };
        client.map_err(|error| DbError::Unavailable(format!("connecting: {error}")))
    }

    /// A connection: a free one, a new one while the pool has room, or the next given back.
    fn take(&self) -> Result<Held<'_>, DbError> {
        let deadline = Instant::now() + self.config.wait;
        loop {
            if let Some(client) = self
                .free
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop()
            {
                if client.is_closed() {
                    *self.open.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
                    continue;
                }
                return Ok(Held {
                    database: self,
                    client: Some(client),
                });
            }
            let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
            if *open < self.config.pool {
                *open += 1;
                drop(open);
                return match self.open() {
                    Ok(client) => Ok(Held {
                        database: self,
                        client: Some(client),
                    }),
                    Err(error) => {
                        *self.open.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
                        self.returned.notify_one();
                        Err(error)
                    }
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(DbError::Unavailable(format!(
                    "every one of the {} connections stayed in use for {:?}",
                    self.config.pool, self.config.wait
                )));
            }
            let _ = self
                .returned
                .wait_timeout(open, left)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Whether the database answers now: what readiness asks.
    pub fn ready(&self) -> Result<(), DbError> {
        Self::apart(|| {
            let mut held = self.take()?;
            let client = held
                .client
                .as_mut()
                .ok_or_else(|| DbError::Unavailable("no connection".to_owned()))?;
            client.simple_query("SELECT 1")?;
            Ok(())
        })?
    }

    /// Runs `work` in one `SERIALIZABLE` transaction and commits it. A transaction the database
    /// could not serialize changed nothing and is run again; `work` may therefore run more than
    /// once and does everything inside the transaction it is given. A refusal of `work` rolls
    /// the transaction back and is answered as it is.
    pub fn transaction<T, E>(
        &self,
        work: impl Fn(&mut Transaction<'_>) -> Result<T, Failure<E>> + Send + Sync,
    ) -> Result<Result<T, E>, DbError>
    where
        T: Send,
        E: Send,
    {
        self.run(IsolationLevel::Serializable, None, &work)
    }

    /// Runs `work` in one transaction that holds `scope` from its first statement to its end:
    /// of the transactions that take one scope, one runs at a time, and each sees what the ones
    /// before it committed. For a rule the rows do not state, and for work that many do at once
    /// on one row, where running it again and again would cost more than waiting in turn.
    ///
    /// The transaction is at `READ COMMITTED`, not `SERIALIZABLE`: a serializable transaction
    /// reads from the moment of its first statement, which is the statement that waits for the
    /// scope, so it would decide on what was there before the holder it waited for committed.
    pub fn under_scope<T, E>(
        &self,
        scope: &str,
        work: impl Fn(&mut Transaction<'_>) -> Result<T, Failure<E>> + Send + Sync,
    ) -> Result<Result<T, E>, DbError>
    where
        T: Send,
        E: Send,
    {
        self.run(IsolationLevel::ReadCommitted, Some(scope), &work)
    }

    fn run<T, E>(
        &self,
        isolation: IsolationLevel,
        scope: Option<&str>,
        work: &(dyn Fn(&mut Transaction<'_>) -> Result<T, Failure<E>> + Send + Sync),
    ) -> Result<Result<T, E>, DbError>
    where
        T: Send,
        E: Send,
    {
        Self::apart(|| {
            let mut last = None;
            for attempt in 1..=ATTEMPTS {
                let mut held = self.take()?;
                let client = held
                    .client
                    .as_mut()
                    .ok_or_else(|| DbError::Unavailable("no connection".to_owned()))?;
                let attempted = (|| {
                    let mut transaction = client
                        .build_transaction()
                        .isolation_level(isolation)
                        .start()?;
                    if let Some(scope) = scope {
                        transaction.execute(
                            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                            &[&scope],
                        )?;
                    }
                    let value = work(&mut transaction)?;
                    transaction.commit()?;
                    Ok::<T, Failure<E>>(value)
                })();
                match attempted {
                    Ok(value) => {
                        self.ended("committed");
                        return Ok(Ok(value));
                    }
                    Err(Failure::Refused(refusal)) => {
                        self.ended("refused");
                        return Ok(Err(refusal));
                    }
                    Err(Failure::Db(error)) if again(&error) => {
                        self.metrics.count(&RETRIES, &[]);
                        last = Some(error);
                        // The connection goes back before the wait: another may use it.
                        drop(held);
                        std::thread::sleep(pause(attempt));
                    }
                    Err(Failure::Db(error)) => {
                        self.ended("failed");
                        return Err(error.into());
                    }
                }
            }
            self.ended("failed");
            Err(DbError::Unavailable(format!(
                "a transaction could not be serialized in {ATTEMPTS} attempts: {}",
                last.map_or_else(String::new, |error| DbError::from(error).to_string())
            )))
        })?
    }

    /// Runs `work` as [`Self::transaction`] does, for work that has no refusal of its own.
    pub fn write<T: Send>(
        &self,
        work: impl Fn(&mut Transaction<'_>) -> Result<T, postgres::Error> + Send + Sync,
    ) -> Result<T, DbError> {
        match self.transaction::<T, std::convert::Infallible>(|transaction| {
            work(transaction).map_err(Failure::Db)
        })? {
            Ok(value) => Ok(value),
            Err(never) => match never {},
        }
    }
}
