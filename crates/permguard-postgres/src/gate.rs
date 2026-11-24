// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A subsystem's gate on PostgreSQL: a row every holder takes inside its unit of work.
//!
//! On files a subsystem is held by a lock of the process. Here its holders may be on several
//! instances, so the gate is a row of `permguard_subsystems` that each of them updates first:
//! the second waits for the first's transaction to end. A holder that is no operation, a token
//! issued, runs in a `READ COMMITTED` unit of its own and then reads what the one before it
//! committed (iteration 03, decisions E25 and E26). A holder that is an operation takes the
//! row in the operation's serializable transaction: had another holder committed since the
//! operation began to read, the database refuses the operation, which kept nothing.

use std::sync::Arc;

use permguard_host::operations::mutation::{Subsystem, SubsystemGate};

use crate::database::{Database, SqlError, Unit};

/// The gate of the subsystem `name` on one database.
#[derive(Debug)]
pub struct PostgresGate {
    database: Database,
    name: String,
}

/// Takes the gate's row in `unit`, to the unit's end.
fn take(unit: &Unit, name: &str) -> Result<(), SqlError> {
    unit.execute(
        "INSERT INTO permguard_subsystems AS held (name, turns) VALUES ($1, 1)
         ON CONFLICT (name) DO UPDATE SET turns = held.turns + 1",
        &[&name],
    )?;
    Ok(())
}

impl PostgresGate {
    /// The subsystem `name` held on `database`: the engine's alone to make.
    pub(crate) fn subsystem(database: Database, name: &str) -> Subsystem {
        Subsystem::over(Arc::new(Self {
            database,
            name: name.to_owned(),
        }))
    }
}

impl SubsystemGate for PostgresGate {
    fn hold(&self, work: &mut dyn FnMut()) -> Result<(), String> {
        if self.database.inside() {
            // Inside an operation: the row is taken in the operation's transaction, and the
            // work is run whatever the database answered. A row that could not be taken left
            // the transaction failed, and the work's own change fails with it.
            let _ = self.database.write(|unit| take(unit, &self.name));
            work();
            return Ok(());
        }
        let unit = self
            .database
            .begin_read_committed()
            .map_err(|error| error.to_string())?;
        take(&unit, &self.name).map_err(|error| error.to_string())?;
        {
            let _inside = self.database.enter(&unit);
            work();
        }
        unit.commit().map_err(|error| error.to_string())
    }
}
