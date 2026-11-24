// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A lease: the right of one instance to do a named piece of work until a time, with a
//! generation that rises each time the lease changes hands.
//!
//! The file backend's fence is the volume claim and its generation; here it is a row. Time is
//! the database's, never an instance's, so two instances whose clocks disagree still agree on
//! who holds a lease. A write made under a lease checks the lease in its own transaction
//! ([`held`], iteration 03 decision E27): an instance that lost it, and does not know yet,
//! cannot write.

use std::time::Duration;

use crate::database::{Database, DbError, Failure, Unit};

/// A lease as its holder was given it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub name: String,
    pub holder: String,
    /// The generation of this holding: every write made under the lease is made under it.
    pub generation: i64,
}

/// The lease is no longer this holder's: it expired and was taken, or was released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost;

fn seconds(ttl: Duration) -> f64 {
    ttl.as_secs_f64()
}

/// Takes the lease `name` for `holder` for `ttl`, when nobody holds it or the holding expired:
/// a new holding, at the next generation. Answers `None` while another holds it. A holder that
/// asks again for a lease it still holds is answered the holding it has, extended.
pub fn acquire(
    database: &Database,
    name: &str,
    holder: &str,
    ttl: Duration,
) -> Result<Option<Lease>, DbError> {
    let ttl = seconds(ttl);
    let generation = database.write(|transaction| {
        let taken = transaction.query_opt(
            "INSERT INTO permguard_leases AS held (name, holder, generation, expires_at)
             VALUES ($1, $2, 1, now() + make_interval(secs => $3))
             ON CONFLICT (name) DO UPDATE SET
                 holder = EXCLUDED.holder,
                 generation = held.generation
                     + CASE WHEN held.holder = EXCLUDED.holder AND held.expires_at > now()
                            THEN 0 ELSE 1 END,
                 expires_at = EXCLUDED.expires_at
             WHERE held.expires_at <= now() OR held.holder = EXCLUDED.holder
             RETURNING generation",
            &[&name, &holder, &ttl],
        )?;
        Ok(taken.map(|row| row.get::<_, i64>(0)))
    })?;
    Ok(generation.map(|generation| Lease {
        name: name.to_owned(),
        holder: holder.to_owned(),
        generation,
    }))
}

/// Extends `lease` by `ttl` from now, while it is still this holding; `Err(Lost)` otherwise.
pub fn renew(
    database: &Database,
    lease: &Lease,
    ttl: Duration,
) -> Result<Result<(), Lost>, DbError> {
    let ttl = seconds(ttl);
    let renewed = database.write(|transaction| {
        transaction.execute(
            "UPDATE permguard_leases SET expires_at = now() + make_interval(secs => $4)
             WHERE name = $1 AND holder = $2 AND generation = $3 AND expires_at > now()",
            &[&lease.name, &lease.holder, &lease.generation, &ttl],
        )
    })?;
    Ok(if renewed == 1 { Ok(()) } else { Err(Lost) })
}

/// Ends `lease` now, so the next asker takes it without waiting for it to expire. Nothing when
/// it is no longer this holding.
pub fn release(database: &Database, lease: &Lease) -> Result<(), DbError> {
    database.write(|transaction| {
        transaction.execute(
            "UPDATE permguard_leases SET expires_at = now()
             WHERE name = $1 AND holder = $2 AND generation = $3 AND expires_at > now()",
            &[&lease.name, &lease.holder, &lease.generation],
        )
    })?;
    Ok(())
}

/// Checks, inside the transaction that writes under `lease`, that the lease is still this
/// holding, and keeps it so until the transaction ends: the write commits only if it was.
pub fn held<E>(unit: &Unit, lease: &Lease, lost: E) -> Result<(), Failure<E>> {
    let row = unit.query_opt(
        "SELECT 1 FROM permguard_leases
         WHERE name = $1 AND holder = $2 AND generation = $3 AND expires_at > now()
         FOR SHARE",
        &[&lease.name, &lease.holder, &lease.generation],
    )?;
    match row {
        Some(_) => Ok(()),
        None => Err(Failure::Refused(lost)),
    }
}
