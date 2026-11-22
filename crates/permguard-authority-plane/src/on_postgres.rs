// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the tests of this Plane's stores on PostgreSQL share: a schema a case, and operations
//! run by the mutation engine of the case's database.

#![allow(clippy::expect_used)]

use std::sync::Mutex;

use permguard_host::operations::journal::Initiator;
use permguard_host::operations::mutation::{Applied, Applying, Begin, run_checked_on};
use permguard_postgres::Database;
use permguard_postgres::mutations::PostgresMutations;
use permguard_postgres::testing::{Scratch, Server, scratch};

/// The cases of one suite: each a schema of its own, kept until the suite ends.
pub struct Cases {
    server: Server,
    made: Mutex<Vec<Scratch>>,
}

impl Cases {
    pub fn new(server: Server) -> Self {
        Self {
            server,
            made: Mutex::new(Vec::new()),
        }
    }

    /// The database of a new case, empty at this build's schema.
    pub fn next(&self) -> Database {
        let case = scratch(&self.server);
        let database = Database::clone(&case.database);
        self.made.lock().expect("lock").push(case);
        database
    }

    /// The database of the case made last.
    pub fn current(&self) -> Database {
        self.made
            .lock()
            .expect("lock")
            .last()
            .map(|case| Database::clone(&case.database))
            .expect("a case was made")
    }

    /// Runs `work` inside one operation of `domain`, applied by the mutation engine of the
    /// current case's database: every store call `work` makes is in that operation's
    /// transaction.
    pub fn operate(&self, domain: &'static str, work: &mut dyn FnMut(&Applying<'_>)) {
        run_checked_on::<(), String>(
            &PostgresMutations::new(self.current()),
            Begin {
                domain,
                operation: "suite.operation",
                action: "suite.operated",
                initiator: Initiator::System("suite".to_owned()),
                request: None,
                target: None,
            },
            || Ok(()),
            |applying| {
                work(applying);
                Ok(Applied {
                    revision: 0,
                    target: None,
                    value: (),
                })
            },
        )
        .expect("the operation ran");
    }
}
