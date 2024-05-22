-- Copyright 2024 Nitro Agility S.r.l.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
CREATE TABLE identities (
    identity_id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	kind SMALLINT NOT NULL,
    name VARCHAR(254) NOT NULL,
	-- REFERENCES
	account_id BIGINT NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	identity_source_id UUID NOT NULL REFERENCES identity_sources(identity_source_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT identities_accountid_identitysourceid_name_key UNIQUE (account_id, identity_source_id, name)
);

CREATE INDEX identities_name_idx ON identities(name);
CREATE INDEX identities_account_id_idx ON identities(account_id);
CREATE INDEX identities_identity_source_id_idx ON identities(identity_source_id);

CREATE TRIGGER bfr_u_identities
	BEFORE UPDATE ON identities
	FOR EACH ROW EXECUTE FUNCTION udf_row_update_timestamp();

CREATE TABLE identities_changestreams (
    changestream_id SERIAL PRIMARY KEY NOT NULL,
	operation VARCHAR(10) NOT NULL,
	operation_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    identity_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
	kind SMALLINT NOT NULL,
    name VARCHAR(254) NOT NULL,
	-- REFERENCES
	account_id BIGINT NOT NULL,
	identity_source_id UUID NOT NULL
);

CREATE INDEX identities_changestreams_name_idx ON identities_changestreams(name);
CREATE INDEX identities_changestreams_account_id_idx ON identities_changestreams(account_id);

-- +goose StatementBegin
CREATE FUNCTION udf_audit_change_for_identities()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO identities_changestreams (operation, identity_id, created_at, updated_at, kind, name, account_id, identity_source_id)
        VALUES (TG_OP, OLD.identity_id, OLD.created_at, OLD.updated_at, OLD.kind, OLD.name, OLD.account_id, OLD.identity_source_id);
        RETURN OLD;
    ELSE
        INSERT INTO identities_changestreams (operation, identity_id, created_at, updated_at, kind, name, account_id, identity_source_id)
        VALUES (TG_OP, NEW.identity_id, NEW.created_at, NEW.updated_at, NEW.kind, NEW.name, NEW.account_id, NEW.identity_source_id);
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE "plpgsql";
-- +goose StatementEnd

CREATE TRIGGER afr_iud_identities_for_changestreams
	AFTER INSERT OR UPDATE OR DELETE ON identities
	FOR EACH ROW EXECUTE FUNCTION udf_audit_change_for_identities();

-- +goose Down
DROP FUNCTION IF EXISTS udf_audit_change_for_identities CASCADE;
DROP TABLE IF EXISTS identities_changestreams CASCADE;

DROP TRIGGER IF EXISTS bfr_u_identities ON identities;
DROP TABLE IF EXISTS identities CASCADE;
