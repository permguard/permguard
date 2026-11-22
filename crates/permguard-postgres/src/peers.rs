// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`SeenStore`]: a row a peer, `permguard_seen_peers`.
//!
//! A presentation is held against the epoch kept in the transaction that writes, so of the
//! sessions established together, on any instance, one with an older presentation never moves
//! the epoch back.

use permguard_host::identity::Verified;
use permguard_host::session::peers::{PeerRefusal, Seen, SeenStore, check};

use crate::database::{Database, DbError, Failure, Unit};

/// The seen epochs of one database.
#[derive(Debug, Clone)]
pub struct PostgresSeen {
    database: Database,
}

fn storage(error: DbError) -> PeerRefusal {
    PeerRefusal::Storage(error.to_string())
}

fn held(unit: &Unit, host_id: &[u8; 16]) -> Result<Option<Seen>, Failure<PeerRefusal>> {
    let Some(row) = unit.query_opt(
        "SELECT epoch, fingerprint, at FROM permguard_seen_peers WHERE host_id = $1",
        &[&host_id.as_slice()],
    )?
    else {
        return Ok(None);
    };
    let unsigned = |value: i64| {
        u64::try_from(value).map_err(|_| {
            Failure::Refused(PeerRefusal::Storage(
                "a seen epoch that does not read".to_owned(),
            ))
        })
    };
    Ok(Some(Seen {
        host_id: *host_id,
        epoch: unsigned(row.get(0))?,
        fingerprint: row.get(1),
        at: unsigned(row.get(2))?,
    }))
}

impl PostgresSeen {
    /// The seen epochs of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}

impl SeenStore for PostgresSeen {
    fn seen(&self, host_id: &[u8; 16]) -> Result<Option<Seen>, PeerRefusal> {
        self.database
            .transaction(|unit| held(unit, host_id))
            .map_err(storage)?
    }

    fn advance(&self, verified: &Verified, at: u64) -> Result<(), PeerRefusal> {
        let kept = |value: u64| {
            i64::try_from(value).map_err(|_| {
                Failure::Refused(PeerRefusal::Storage(
                    "an epoch past what the store keeps".to_owned(),
                ))
            })
        };
        self.database
            .transaction(|unit| {
                if let Some(seen) = held(unit, &verified.host_id)? {
                    check(&seen, verified).map_err(Failure::Refused)?;
                    if seen.epoch == verified.epoch {
                        return Ok(());
                    }
                }
                unit.execute(
                    "INSERT INTO permguard_seen_peers AS held (host_id, epoch, fingerprint, at)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (host_id) DO UPDATE SET
                         epoch = EXCLUDED.epoch, fingerprint = EXCLUDED.fingerprint,
                         at = EXCLUDED.at
                     WHERE held.epoch < EXCLUDED.epoch",
                    &[
                        &verified.host_id.as_slice(),
                        &kept(verified.epoch)?,
                        &verified.fingerprint(),
                        &kept(at)?,
                    ],
                )?;
                Ok(())
            })
            .map_err(storage)?
    }
}
