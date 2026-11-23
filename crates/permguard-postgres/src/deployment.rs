// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The deployment a database keeps (iteration 03, WP-28.1): the id its Host identity is
//! provisioned and opened under, `permguard_deployment`, one row.
//!
//! On files the identity is bound to the volume's id; here it is bound to the deployment's, the
//! same for every instance. It is minted once, by the first start, or written by the import of a
//! volume, which keeps the volume's own: the identity it carries names it.
//!
//! | Writer       | Writes                                                                     |
//! | ------------ | -------------------------------------------------------------------------- |
//! | a start      | a fresh id, when the database holds none                                   |
//! | an import    | the volume's id, importing, into a database that holds none; cleared last |

use crate::database::{Database, DbError};

/// The deployment a database keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    /// The id the Host identity is provisioned and opened under.
    pub id: [u8; 16],
    /// Whether an import of a volume began on the database and did not complete: no start
    /// serves it, and the database is emptied before the import runs again.
    pub importing: bool,
}

fn id_of(held: Vec<u8>) -> Result<[u8; 16], DbError> {
    <[u8; 16]>::try_from(held)
        .map_err(|_| DbError::Record("the deployment's id is not 16 bytes".to_owned()))
}

/// The deployment, its id minted by the first caller when the database holds none: of the
/// callers that find none together, on any instance, one writes it and every caller is answered
/// it.
pub fn home(database: &Database) -> Result<Deployment, DbError> {
    let (held, importing): (Vec<u8>, bool) = database.write(|unit| {
        unit.execute(
            "INSERT INTO permguard_deployment (id) VALUES (uuid_send(gen_random_uuid()))
             ON CONFLICT (only_one) DO NOTHING",
            &[],
        )?;
        let row = unit.query_one("SELECT id, importing FROM permguard_deployment", &[])?;
        Ok((row.get(0), row.get(1)))
    })?;
    Ok(Deployment {
        id: id_of(held)?,
        importing,
    })
}

/// Begins the import of the volume whose id is `id`: the deployment written as `id`, importing.
/// Answers `false`, writing nothing, when the database already keeps a deployment: a server
/// started on it, or another import began. An import writes into a database that holds nothing.
pub fn begin_import(database: &Database, id: &[u8; 16]) -> Result<bool, DbError> {
    let written = database.write(|unit| {
        unit.execute(
            "INSERT INTO permguard_deployment (id, importing) VALUES ($1, true)
             ON CONFLICT (only_one) DO NOTHING",
            &[&id.as_slice()],
        )
    })?;
    Ok(written == 1)
}

/// Completes the import [`begin_import`] began for `id`: from here a start serves the database.
/// Answers `false` when the database keeps no import of `id` under way.
pub fn complete_import(database: &Database, id: &[u8; 16]) -> Result<bool, DbError> {
    let cleared = database.write(|unit| {
        unit.execute(
            "UPDATE permguard_deployment SET importing = false WHERE id = $1 AND importing",
            &[&id.as_slice()],
        )
    })?;
    Ok(cleared == 1)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::testing::{Cases, server};

    /// The id is minted once and answered to every caller after; an import into a database that
    /// keeps a deployment writes nothing.
    #[test]
    fn the_deployment_is_minted_once_on_postgresql() {
        let Some(server) = server("the_deployment_is_minted_once_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        let first = home(&database).expect("minted");
        assert!(!first.importing);
        assert_eq!(home(&database).expect("read"), first);
        assert!(!begin_import(&database, &[7; 16]).expect("answered"));
        assert!(!begin_import(&database, &first.id).expect("answered"));
        assert!(!complete_import(&database, &first.id).expect("answered"));
        assert_eq!(home(&database).expect("read"), first);
    }

    /// An import is under way from its beginning to its completion, and the deployment is the
    /// volume's: a second import does not begin over it, and a start reads it as importing.
    #[test]
    fn an_import_is_under_way_until_it_completes_on_postgresql() {
        let Some(server) = server("an_import_is_under_way_until_it_completes_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        assert!(begin_import(&database, &[7; 16]).expect("begun"));
        assert!(!begin_import(&database, &[7; 16]).expect("answered"));
        assert_eq!(
            home(&database).expect("read"),
            Deployment {
                id: [7; 16],
                importing: true
            }
        );
        assert!(!complete_import(&database, &[8; 16]).expect("answered"));
        assert!(complete_import(&database, &[7; 16]).expect("completed"));
        assert!(!complete_import(&database, &[7; 16]).expect("answered"));
        assert_eq!(
            home(&database).expect("read"),
            Deployment {
                id: [7; 16],
                importing: false
            }
        );
    }
}
