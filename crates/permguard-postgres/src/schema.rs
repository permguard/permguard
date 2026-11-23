// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The schema: versioned, forward only, checked at start (iteration 03, decision E29).
//!
//! A migration is a number, a name and the statements that take the schema from the version
//! before it. Migrations are applied in order, each recorded in `permguard_schema` in the
//! transaction that applies it, by whichever instance starts first: the others wait for it and
//! find nothing left to apply. A migration is never edited once released and none goes back.
//! A database whose schema is newer than this build knows is not served by it.

use crate::database::{Database, DbError, Failure, Unit};

/// One step of the schema.
pub struct Migration {
    pub version: i32,
    pub name: &'static str,
    pub statements: &'static str,
}

/// Every migration, oldest first, their versions counting from 1 with no gap.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "foundations",
        statements: "
        CREATE TABLE permguard_leases (
            name text PRIMARY KEY,
            holder text NOT NULL,
            generation bigint NOT NULL CHECK (generation > 0),
            expires_at timestamptz NOT NULL
        );
        CREATE TABLE permguard_clock_marks (
            scope text PRIMARY KEY,
            mark bigint NOT NULL
        );
    ",
    },
    Migration {
        version: 2,
        name: "mutations",
        statements: "
        CREATE TABLE permguard_mutations (
            operation_id bytea PRIMARY KEY CHECK (octet_length(operation_id) = 16),
            domain text NOT NULL,
            operation text NOT NULL,
            action text NOT NULL,
            initiator_kind text NOT NULL CHECK (initiator_kind IN ('principal', 'system')),
            initiator text NOT NULL,
            request_id text,
            request_digest text,
            target text,
            state text NOT NULL CHECK (state IN ('applied', 'failed')),
            revision bigint CHECK (revision >= 0),
            result bytea,
            at timestamptz NOT NULL DEFAULT now(),
            CHECK ((request_id IS NULL) = (request_digest IS NULL))
        );
        CREATE UNIQUE INDEX permguard_mutations_request
            ON permguard_mutations (initiator, request_id)
            WHERE request_id IS NOT NULL AND initiator_kind = 'principal' AND state = 'applied';
        CREATE TABLE permguard_mutation_audit (
            sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            operation_id bytea NOT NULL REFERENCES permguard_mutations (operation_id),
            phase text NOT NULL CHECK (phase IN ('intent', 'applied', 'failed')),
            action text NOT NULL,
            subject_kind text NOT NULL CHECK (subject_kind IN ('principal', 'system')),
            subject text NOT NULL,
            target text,
            at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (operation_id, phase)
        );
    ",
    },
    Migration {
        version: 3,
        name: "authority accounts",
        statements: "
        CREATE TABLE permguard_authority_revisions (
            store text PRIMARY KEY,
            revision bigint NOT NULL CHECK (revision >= 0)
        );
        INSERT INTO permguard_authority_revisions (store, revision) VALUES ('accounts', 0);
        CREATE TABLE permguard_authority_accounts (
            name text PRIMARY KEY,
            description text NOT NULL,
            status text NOT NULL CHECK (status IN ('active', 'suspended')),
            created_at bigint NOT NULL,
            updated_at bigint NOT NULL,
            revision bigint NOT NULL CHECK (revision > 0),
            updated_by text NOT NULL
        );
        CREATE TABLE permguard_authority_scopes (
            account text NOT NULL REFERENCES permguard_authority_accounts (name) ON DELETE CASCADE,
            position integer NOT NULL CHECK (position >= 0),
            operations text[] NOT NULL,
            selector text NOT NULL,
            PRIMARY KEY (account, position)
        );
        CREATE TABLE permguard_authority_access_keys (
            access_key text PRIMARY KEY,
            account text NOT NULL REFERENCES permguard_authority_accounts (name) ON DELETE CASCADE,
            position integer NOT NULL CHECK (position >= 0),
            secret_hash text NOT NULL,
            created_at bigint NOT NULL,
            expires_at bigint,
            UNIQUE (account, position)
        );
        CREATE TABLE permguard_authority_account_operations (
            operation_id bytea PRIMARY KEY CHECK (octet_length(operation_id) = 16),
            revision bigint NOT NULL,
            account text NOT NULL
        );
    ",
    },
    Migration {
        version: 4,
        name: "subsystems and authority tokens",
        statements: "
        CREATE TABLE permguard_subsystems (
            name text PRIMARY KEY,
            turns bigint NOT NULL CHECK (turns > 0)
        );
        INSERT INTO permguard_authority_revisions (store, revision) VALUES ('tokens', 0);
        CREATE TABLE permguard_authority_lists (
            list_id bytea PRIMARY KEY CHECK (octet_length(list_id) = 16),
            open boolean NOT NULL,
            drawn integer NOT NULL CHECK (drawn >= 0),
            latest_expiry bigint NOT NULL,
            changed_at bigint NOT NULL
        );
        CREATE UNIQUE INDEX permguard_authority_lists_open
            ON permguard_authority_lists (open) WHERE open;
        CREATE TABLE permguard_authority_tokens (
            jti bytea PRIMARY KEY CHECK (octet_length(jti) = 16),
            list_id bytea NOT NULL REFERENCES permguard_authority_lists (list_id) ON DELETE CASCADE,
            entry integer NOT NULL CHECK (entry >= 0),
            account text NOT NULL,
            access_key text NOT NULL,
            issued_at bigint NOT NULL,
            expires_at bigint NOT NULL,
            status smallint NOT NULL CHECK (status IN (0, 1, 2)),
            UNIQUE (list_id, entry)
        );
        CREATE INDEX permguard_authority_tokens_access_key
            ON permguard_authority_tokens (access_key);
        CREATE TABLE permguard_authority_token_scopes (
            jti bytea NOT NULL REFERENCES permguard_authority_tokens (jti) ON DELETE CASCADE,
            position integer NOT NULL CHECK (position >= 0),
            operations text[] NOT NULL,
            selector text NOT NULL,
            PRIMARY KEY (jti, position)
        );
        CREATE TABLE permguard_authority_token_operations (
            operation_id bytea PRIMARY KEY CHECK (octet_length(operation_id) = 16),
            revision bigint NOT NULL,
            named text NOT NULL
        );
        CREATE TABLE permguard_authority_marks (
            list_id bytea PRIMARY KEY CHECK (octet_length(list_id) = 16),
            mark bigint NOT NULL
        );
    ",
    },
    Migration {
        version: 5,
        name: "holds",
        statements: "
        CREATE TABLE permguard_holds (
            id text PRIMARY KEY,
            resource text NOT NULL,
            owner text NOT NULL,
            reason text NOT NULL,
            created_at bigint NOT NULL,
            expires_at bigint,
            review_at bigint,
            operation text
        );
    ",
    },
    Migration {
        version: 6,
        name: "seen peers and the bootstrap commitment",
        statements: "
        CREATE TABLE permguard_seen_peers (
            host_id bytea PRIMARY KEY CHECK (octet_length(host_id) = 16),
            epoch bigint NOT NULL CHECK (epoch > 0),
            fingerprint text NOT NULL,
            at bigint NOT NULL
        );
        CREATE TABLE permguard_bootstrap (
            only_one boolean PRIMARY KEY DEFAULT true CHECK (only_one),
            principal text NOT NULL,
            fingerprint text NOT NULL,
            created_at bigint NOT NULL
        );
    ",
    },
    Migration {
        version: 7,
        name: "witnesses and what a Host holds of the Authority Plane",
        statements: "
        CREATE TABLE permguard_witnesses (
            name text PRIMARY KEY,
            witness bytea NOT NULL
        );
        CREATE TABLE permguard_version_witnesses (
            scope text NOT NULL,
            position integer NOT NULL CHECK (position >= 0),
            label text NOT NULL,
            witness text NOT NULL,
            PRIMARY KEY (scope, position)
        );
        CREATE TABLE permguard_held_keys (
            only_one boolean PRIMARY KEY DEFAULT true CHECK (only_one),
            key_set text NOT NULL
        );
        CREATE TABLE permguard_held_lists (
            issuer text NOT NULL,
            uri text NOT NULL,
            iat bigint NOT NULL,
            token text NOT NULL,
            PRIMARY KEY (issuer, uri)
        );
    ",
    },
    Migration {
        version: 8,
        name: "plans",
        statements: "
        CREATE TABLE permguard_plans (
            principal text NOT NULL,
            plan_id text NOT NULL,
            record text NOT NULL,
            expires bigint NOT NULL,
            consumed boolean NOT NULL,
            PRIMARY KEY (principal, plan_id)
        );
        CREATE INDEX permguard_plans_id ON permguard_plans (plan_id);
    ",
    },
    Migration {
        version: 9,
        name: "identity, rings and memberships",
        statements: "
        CREATE TABLE permguard_identity_records (
            name text PRIMARY KEY CHECK (name IN ('init', 'document', 'start', 'resetting')),
            record bytea NOT NULL
        );
        CREATE TABLE permguard_identity_successions (
            position bigint PRIMARY KEY CHECK (position > 0),
            envelope bytea NOT NULL
        );
        CREATE TABLE permguard_identity_public_keys (
            epoch bigint PRIMARY KEY CHECK (epoch > 0),
            key bytea NOT NULL
        );
        CREATE TABLE permguard_identity_retired (
            host_id text PRIMARY KEY,
            reset bytea NOT NULL
        );
        CREATE TABLE permguard_identity_evidence (
            host_id text NOT NULL REFERENCES permguard_identity_retired (host_id) ON DELETE CASCADE,
            kind text NOT NULL CHECK (kind IN ('init', 'document', 'succession', 'public')),
            position bigint NOT NULL,
            record bytea NOT NULL,
            PRIMARY KEY (host_id, kind, position)
        );
        CREATE TABLE permguard_ring_entries (
            ring text NOT NULL,
            seq bigint NOT NULL CHECK (seq > 0),
            entry bytea NOT NULL,
            PRIMARY KEY (ring, seq)
        );
        CREATE TABLE permguard_ring_records (
            ring text NOT NULL,
            name text NOT NULL CHECK (name IN ('view', 'binding')),
            record bytea NOT NULL,
            PRIMARY KEY (ring, name)
        );
        CREATE TABLE permguard_ring_kept_bindings (
            ring text NOT NULL,
            seq bigint NOT NULL,
            envelope bytea NOT NULL,
            PRIMARY KEY (ring, seq)
        );
        CREATE TABLE permguard_ring_public_keys (
            ring text NOT NULL,
            thumbprint text NOT NULL,
            jwk bytea NOT NULL,
            PRIMARY KEY (ring, thumbprint)
        );
        CREATE TABLE permguard_ring_evidence (
            ring text NOT NULL,
            host_id text NOT NULL,
            kind text NOT NULL CHECK (kind IN ('entry', 'record', 'kept binding', 'public key')),
            name text NOT NULL,
            record bytea NOT NULL,
            PRIMARY KEY (ring, host_id, kind, name)
        );
        CREATE TABLE permguard_member_entries (
            seq bigint PRIMARY KEY CHECK (seq > 0),
            entry bytea NOT NULL
        );
        CREATE TABLE permguard_member_views (
            kind text NOT NULL CHECK (kind IN ('summary', 'manifest', 'invitation')),
            name text NOT NULL,
            record bytea NOT NULL,
            PRIMARY KEY (kind, name)
        );
        CREATE TABLE permguard_member_documents (
            kind text NOT NULL,
            owner bytea NOT NULL CHECK (octet_length(owner) = 16),
            scope text NOT NULL,
            name text NOT NULL,
            record bytea NOT NULL,
            PRIMARY KEY (kind, owner, scope, name)
        );
        CREATE TABLE permguard_member_checkpoints (
            membership bytea NOT NULL CHECK (octet_length(membership) = 16),
            trail text NOT NULL,
            count bigint NOT NULL CHECK (count > 0),
            envelope bytea NOT NULL,
            PRIMARY KEY (membership, trail, count)
        );
    ",
    },
    Migration {
        version: 10,
        name: "catalog",
        statements: "
        CREATE TABLE permguard_zones (
            id text PRIMARY KEY,
            position bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
            name text NOT NULL UNIQUE,
            created_at bigint NOT NULL,
            updated_at bigint NOT NULL,
            revision bigint NOT NULL CHECK (revision > 0),
            operation text
        );
        CREATE TABLE permguard_ledgers (
            id text PRIMARY KEY,
            position bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
            zone_id text NOT NULL REFERENCES permguard_zones (id),
            name text NOT NULL,
            default_ref text NOT NULL,
            created_at bigint NOT NULL,
            updated_at bigint NOT NULL,
            revision bigint NOT NULL CHECK (revision > 0),
            operation text,
            state text NOT NULL CHECK (state IN ('active', 'archived')),
            provenance text,
            UNIQUE (zone_id, name)
        );
        CREATE TABLE permguard_catalog_tombstones (
            id text PRIMARY KEY,
            zone_id text,
            name text NOT NULL,
            deleted_at bigint NOT NULL,
            revision bigint NOT NULL,
            operation text
        );
        CREATE TABLE permguard_catalog_marks (
            scope text NOT NULL,
            name text NOT NULL,
            reached bigint NOT NULL,
            PRIMARY KEY (scope, name)
        );
    ",
    },
    Migration {
        version: 11,
        name: "ledgers",
        statements: "
        CREATE TABLE permguard_ledger_refs (
            zone text NOT NULL,
            ledger text NOT NULL,
            name text NOT NULL,
            head text NOT NULL,
            counter bigint NOT NULL CHECK (counter > 0),
            previous text,
            operation text NOT NULL,
            PRIMARY KEY (zone, ledger, name)
        );
        CREATE TABLE permguard_ledger_statements (
            zone text NOT NULL,
            ledger text NOT NULL,
            name text NOT NULL,
            envelope bytea NOT NULL,
            PRIMARY KEY (zone, ledger, name)
        );
        CREATE TABLE permguard_ledger_roots (
            zone text NOT NULL,
            ledger text NOT NULL,
            head text NOT NULL,
            PRIMARY KEY (zone, ledger, head)
        );
        CREATE TABLE permguard_ledger_transfers (
            zone text NOT NULL,
            ledger text NOT NULL,
            transfer_id bytea NOT NULL CHECK (octet_length(transfer_id) = 16),
            record bytea NOT NULL,
            PRIMARY KEY (zone, ledger, transfer_id)
        );
    ",
    },
    Migration {
        version: 12,
        name: "archives",
        statements: "
        CREATE TABLE permguard_archives (
            zone text NOT NULL,
            id text NOT NULL,
            name text NOT NULL,
            request_id text NOT NULL,
            record text NOT NULL,
            requested text NOT NULL,
            PRIMARY KEY (zone, id),
            UNIQUE (zone, name),
            UNIQUE (zone, request_id)
        );
    ",
    },
    Migration {
        version: 13,
        name: "audit trails",
        statements: "
        CREATE TABLE permguard_audit_trails (
            class text NOT NULL CHECK (class IN ('security', 'operations', 'access')),
            digest text NOT NULL,
            resource text NOT NULL,
            meta bytea NOT NULL,
            next_seq bigint NOT NULL CHECK (next_seq >= 0),
            previous bytea NOT NULL CHECK (octet_length(previous) = 32),
            last_day text,
            sealed text,
            checkpoint_name text,
            checkpoint_digest bytea CHECK (octet_length(checkpoint_digest) = 32),
            checkpoint_last_seq bigint,
            checkpoint_head bytea CHECK (octet_length(checkpoint_head) = 32),
            anchor bytea,
            PRIMARY KEY (class, digest),
            CHECK ((checkpoint_name IS NULL) = (checkpoint_digest IS NULL)),
            CHECK ((checkpoint_name IS NULL) = (checkpoint_last_seq IS NULL)),
            CHECK ((checkpoint_name IS NULL) = (checkpoint_head IS NULL))
        );
        CREATE TABLE permguard_audit_days (
            class text NOT NULL,
            digest text NOT NULL,
            day text NOT NULL,
            archived boolean NOT NULL DEFAULT false,
            PRIMARY KEY (class, digest, day),
            FOREIGN KEY (class, digest) REFERENCES permguard_audit_trails (class, digest)
        );
        CREATE TABLE permguard_audit_records (
            class text NOT NULL,
            digest text NOT NULL,
            seq bigint NOT NULL CHECK (seq >= 0),
            day text NOT NULL,
            record bytea NOT NULL,
            PRIMARY KEY (class, digest, seq),
            FOREIGN KEY (class, digest, day)
                REFERENCES permguard_audit_days (class, digest, day)
        );
        CREATE INDEX permguard_audit_records_day
            ON permguard_audit_records (class, digest, day, seq);
        CREATE TABLE permguard_audit_checkpoints (
            class text NOT NULL,
            digest text NOT NULL,
            name text NOT NULL,
            envelope bytea NOT NULL,
            archived boolean NOT NULL DEFAULT false,
            PRIMARY KEY (class, digest, name),
            FOREIGN KEY (class, digest) REFERENCES permguard_audit_trails (class, digest)
        );
    ",
    },
    Migration {
        version: 14,
        name: "the audit record of a mutation is in the trail",
        statements: "
        DROP TABLE permguard_mutation_audit;
    ",
    },
    Migration {
        version: 15,
        name: "settled audit days",
        statements: "
        CREATE TABLE permguard_audit_doomed (
            key text PRIMARY KEY
        );
    ",
    },
    Migration {
        version: 16,
        name: "stream consumers",
        statements: "
        CREATE TABLE permguard_stream_runs (
            consumer text NOT NULL,
            component text NOT NULL,
            producer text NOT NULL,
            run text NOT NULL,
            first_index bigint NOT NULL CHECK (first_index >= 0),
            next_index bigint NOT NULL CHECK (next_index >= first_index),
            PRIMARY KEY (consumer, component, producer, run)
        );
        CREATE TABLE permguard_stream_frames (
            consumer text NOT NULL,
            component text NOT NULL,
            producer text NOT NULL,
            run text NOT NULL,
            idx bigint NOT NULL CHECK (idx >= 0),
            kind integer NOT NULL CHECK (kind BETWEEN 0 AND 65535),
            payload bytea NOT NULL,
            PRIMARY KEY (consumer, component, producer, run, idx),
            FOREIGN KEY (consumer, component, producer, run)
                REFERENCES permguard_stream_runs (consumer, component, producer, run)
        );
        CREATE TABLE permguard_stream_views (
            consumer text NOT NULL,
            component text NOT NULL,
            producer text NOT NULL,
            run text NOT NULL,
            name text NOT NULL,
            bytes bytea NOT NULL,
            PRIMARY KEY (consumer, component, producer, run, name)
        );
        CREATE TABLE permguard_stream_shelves (
            consumer text NOT NULL,
            component text NOT NULL,
            producer text NOT NULL,
            run text NOT NULL,
            shelf text NOT NULL,
            name text NOT NULL,
            PRIMARY KEY (consumer, component, producer, run, shelf, name),
            FOREIGN KEY (consumer, component, producer, run)
                REFERENCES permguard_stream_runs (consumer, component, producer, run)
        );
    ",
    },
    Migration {
        version: 17,
        name: "key slots",
        statements: "
        CREATE TABLE permguard_key_slots (
            scope text NOT NULL,
            kind text NOT NULL CHECK (kind IN ('key', 'reference')),
            slot text NOT NULL,
            bytes bytea NOT NULL,
            PRIMARY KEY (scope, kind, slot)
        );
    ",
    },
    Migration {
        version: 18,
        name: "sealed secrets",
        statements: "
        CREATE TABLE permguard_delivered_keys (
            authority bytea NOT NULL CHECK (octet_length(authority) = 16),
            zone bytea NOT NULL CHECK (octet_length(zone) = 16),
            purpose text NOT NULL,
            scope bytea NOT NULL CHECK (octet_length(scope) = 16),
            version bigint NOT NULL CHECK (version >= 1),
            kek_ref text NOT NULL,
            kek_version bigint NOT NULL,
            wrap_algorithm text NOT NULL,
            wrapped bytea NOT NULL,
            PRIMARY KEY (authority, zone, purpose, scope, version)
        );
        CREATE TABLE permguard_cursor_roots (
            store text PRIMARY KEY,
            kek_ref text,
            kek_version bigint,
            wrap_algorithm text,
            wrapped bytea,
            previous_kek_ref text,
            previous_kek_version bigint,
            previous_wrap_algorithm text,
            previous_wrapped bytea,
            CHECK ((kek_ref IS NULL) = (wrapped IS NULL)),
            CHECK ((previous_kek_ref IS NULL) = (previous_wrapped IS NULL))
        );
    ",
    },
    Migration {
        version: 19,
        name: "refs written before the transaction",
        // A ref a build before WP-3.6 wrote names no operation, on files as here: an import
        // keeps it so (iteration 03, WP-27.6).
        statements: "
        ALTER TABLE permguard_ledger_refs ALTER COLUMN operation DROP NOT NULL;
    ",
    },
    Migration {
        version: 20,
        name: "the deployment",
        // The id the Host identity is provisioned and opened under, as a volume's id is on files
        // (iteration 03, WP-28.1): one row, minted once, or written by the import of a volume.
        statements: "
        CREATE TABLE permguard_deployment (
            only_one boolean PRIMARY KEY DEFAULT true CHECK (only_one),
            id bytea NOT NULL CHECK (octet_length(id) = 16)
        );
    ",
    },
    Migration {
        version: 21,
        name: "an import under way",
        // The import of a volume writes the deployment first, as importing, and clears it last:
        // a start refuses a database an import did not complete (iteration 03, WP-28.1).
        statements: "
        ALTER TABLE permguard_deployment ADD COLUMN importing boolean NOT NULL DEFAULT false;
    ",
    },
];

/// The version this build's schema is at.
pub fn known() -> i32 {
    MIGRATIONS.last().map_or(0, |migration| migration.version)
}

/// The version the database's schema is at; 0 for a database that holds none yet.
fn version(unit: &Unit) -> Result<i32, crate::database::SqlError> {
    unit.batch_execute(
        "CREATE TABLE IF NOT EXISTS permguard_schema (
            version integer PRIMARY KEY CHECK (version > 0),
            name text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now()
        )",
    )?;
    Ok(unit
        .query_one(
            "SELECT COALESCE(MAX(version), 0) FROM permguard_schema",
            &[],
        )?
        .get(0))
}

/// Brings the database's schema to this build's, applying what is missing, and answers the
/// version it is at. One instance applies at a time. A schema newer than this build knows is
/// [`DbError::SchemaNewer`] and nothing is changed.
pub fn migrate(database: &Database) -> Result<i32, DbError> {
    database.under_scope("schema migrations", |transaction| {
        let found = version(transaction)?;
        if found > known() {
            return Err(Failure::Refused(DbError::SchemaNewer {
                found,
                known: known(),
            }));
        }
        for migration in MIGRATIONS.iter().filter(|step| step.version > found) {
            transaction.batch_execute(migration.statements)?;
            transaction.execute(
                "INSERT INTO permguard_schema (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )?;
        }
        Ok(known())
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A migration released is never renumbered: versions count from 1 with no gap, so the
    /// highest version is how many were applied.
    #[test]
    fn the_migrations_are_numbered_from_1_with_no_gap() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migration.version, index as i32 + 1, "{}", migration.name);
            assert!(!migration.name.is_empty() && !migration.statements.trim().is_empty());
        }
        assert_eq!(known(), MIGRATIONS.len() as i32);
    }
}
