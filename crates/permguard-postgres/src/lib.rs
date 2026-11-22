// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL side of the second storage backend (`1-architecture/8` Storage backends):
//! what every store contract implemented on PostgreSQL is built on.
//!
//! | Module       | What it is                                                                      |
//! | ------------ | ------------------------------------------------------------------------------- |
//! | [`database`] | the connections, their TLS, and the unit of work: one `SERIALIZABLE` transaction |
//! | [`schema`]   | the versioned schema, forward only, checked at start                            |
//! | [`lease`]    | a lease with a generation, checked inside the transaction that writes under it  |
//! | [`time`]     | the clock's high-water mark, the first store contract kept here                 |
//!
//! The store contracts are synchronous, as the file backend's calls are, and are called from
//! threads that drive asynchronous tasks. So this crate uses the synchronous client, and a call
//! to it made from such a thread is run on a thread of its own: the client blocks on a runtime
//! it owns, which a thread already inside a runtime may not do.
//!
//! A thread is inside one unit of work at a time. While the mutation engine applies an operation,
//! everything a store of this crate does on that thread, a read or a change, it does inside the
//! operation's transaction: a domain write reads what it wrote, and every store it changes
//! changes with it or not at all.
//!
//! No state is kept in memory: every decision reads inside its transaction.

pub mod bootstrap;
pub mod catalog;
pub mod database;
pub mod gate;
pub mod held;
pub mod holds;
pub mod identity;
pub mod lease;
pub mod members;
pub mod mutations;
pub mod peers;
pub mod replay;
pub mod ring;
pub mod schema;
#[cfg(feature = "test-support")]
pub mod testing;
pub mod time;
pub mod witnesses;

pub use database::{Config, Database, DbError, Failure, SqlError, Tls, Unit};
/// What a statement's parameter is: named here so a store kept on this backend in another
/// crate links the client through this one alone.
pub use postgres::types::ToSql;
