// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the tests of this backend share: where the test server is, and a schema of a test's own.

#![allow(clippy::expect_used, clippy::panic, dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use permguard_postgres::database::DEFAULT_WAIT;
use permguard_postgres::{Config, Database, Tls, schema};

pub const VARIABLE: &str = "PERMGUARD_TEST_POSTGRES";

/// Where the test server is, or `None` with a line saying the test was skipped.
pub fn server(test: &str) -> Option<postgres::Config> {
    match std::env::var(VARIABLE) {
        Ok(text) => Some(text.parse().expect("a connection string")),
        Err(_) => {
            eprintln!("{test}: skipped, {VARIABLE} names no PostgreSQL");
            None
        }
    }
}

/// A database of the test server, in a schema of its own, migrated; the schema is dropped when
/// the answer is.
pub struct Scratch {
    pub database: Arc<Database>,
    admin: Config,
    pub schema: String,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Ok(admin) = Database::connect(self.admin.clone()) {
            let statement = format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema);
            let _ = admin.write(|transaction| transaction.batch_execute(&statement));
        }
    }
}

pub fn config(server: &postgres::Config, schema: Option<String>, pool: usize) -> Config {
    let host = match server.get_hosts().first().expect("a host") {
        postgres::config::Host::Tcp(host) => host.clone(),
        #[cfg(unix)]
        postgres::config::Host::Unix(_) => panic!("{VARIABLE} names a TCP host"),
    };
    Config {
        host,
        port: server.get_ports().first().copied().unwrap_or(5432),
        database: server.get_dbname().expect("a database").to_owned(),
        user: server.get_user().expect("a user").to_owned(),
        password: server
            .get_password()
            .map(|password| String::from_utf8(password.to_vec()).expect("a UTF-8 password")),
        schema,
        tls: Tls::Disabled,
        pool,
        wait: DEFAULT_WAIT,
    }
}

pub fn scratch_with(server: &postgres::Config, pool: usize, migrated: bool) -> Scratch {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let schema = format!(
        "t{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let admin = config(server, None, 1);
    let statement = format!("CREATE SCHEMA {schema}");
    Database::connect(admin.clone())
        .expect("the test server answers")
        .write(|transaction| transaction.batch_execute(&statement))
        .expect("a schema of the test's own");
    let database =
        Arc::new(Database::connect(config(server, Some(schema.clone()), pool)).expect("connected"));
    if migrated {
        assert_eq!(
            schema::migrate(&database).expect("migrated"),
            schema::known()
        );
    }
    Scratch {
        database,
        admin,
        schema,
    }
}

pub fn scratch(server: &postgres::Config) -> Scratch {
    scratch_with(server, 8, true)
}
