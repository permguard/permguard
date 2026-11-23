// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The deployment a database keeps (iteration 03, WP-28.1): the id its Host identity is
//! provisioned and opened under, `permguard_deployment`, one row.
//!
//! On files the identity is bound to the volume's id; here it is bound to the deployment's, the
//! same for every instance. It is minted once, by the first start, or written by the import of a
//! volume, which keeps the volume's own: the identity it carries names it.

use crate::database::{Database, DbError};

/// The deployment's id, minted by the first caller when the database holds none: of the callers
/// that find none together, on any instance, one writes it and every caller is answered it.
pub fn home(database: &Database) -> Result<[u8; 16], DbError> {
    let held: Vec<u8> = database.write(|unit| {
        unit.execute(
            "INSERT INTO permguard_deployment (id) VALUES (uuid_send(gen_random_uuid()))
             ON CONFLICT (only_one) DO NOTHING",
            &[],
        )?;
        Ok(unit
            .query_one("SELECT id FROM permguard_deployment", &[])?
            .get(0))
    })?;
    <[u8; 16]>::try_from(held)
        .map_err(|_| DbError::Record("the deployment's id is not 16 bytes".to_owned()))
}

/// Writes `id` as the deployment's: the import of a volume, whose identity names the volume's
/// id. A database that holds another refuses; the same again is written once.
pub fn import(database: &Database, id: &[u8; 16]) -> Result<(), DbError> {
    let held: Vec<u8> = database.write(|unit| {
        unit.execute(
            "INSERT INTO permguard_deployment (id) VALUES ($1) ON CONFLICT (only_one) DO NOTHING",
            &[&id.as_slice()],
        )?;
        Ok(unit
            .query_one("SELECT id FROM permguard_deployment", &[])?
            .get(0))
    })?;
    if held.as_slice() == id {
        Ok(())
    } else {
        Err(DbError::Record(
            "the database is another deployment's: it keeps another id".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::testing::{Cases, server};

    /// The id is minted once and answered to every caller after; an import of another refuses,
    /// and the import of the same is written once.
    #[test]
    fn the_deployment_is_minted_once_on_postgresql() {
        let Some(server) = server("the_deployment_is_minted_once_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        let first = home(&database).expect("minted");
        assert_eq!(home(&database).expect("read"), first);
        assert!(import(&database, &[7; 16]).is_err());
        import(&database, &first).expect("the same");

        let imported = cases.next();
        import(&imported, &[7; 16]).expect("written");
        assert_eq!(home(&imported).expect("read"), [7; 16]);
    }
}
