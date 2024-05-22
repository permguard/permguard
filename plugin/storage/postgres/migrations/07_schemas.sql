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
CREATE TABLE schemas (
    schema_id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	domains JSONB NOT NULL DEFAULT '{}',
	-- REFERENCES
	account_id BIGINT NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	repository_id UUID NOT NULL REFERENCES repositories(repository_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT schemas_accountid_repository_id_key UNIQUE (account_id, repository_id)
);

CREATE INDEX schemas_account_id_idx ON schemas(account_id);
CREATE INDEX schemas_account_repository_id_idx ON schemas(repository_id);

CREATE TRIGGER bfr_u_schemas
	BEFORE UPDATE ON schemas
	FOR EACH ROW EXECUTE FUNCTION udf_row_update_timestamp();

CREATE TABLE schemas_changestreams (
    changestream_id SERIAL PRIMARY KEY NOT NULL,
	operation VARCHAR(10) NOT NULL,
	operation_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    schema_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
	domains JSONB NOT NULL DEFAULT '{}',
	-- REFERENCES
	account_id BIGINT NOT NULL,
	repository_id UUID NOT NULL
);

CREATE INDEX schemas_changestreams_account_id_idx ON schemas_changestreams(account_id);
CREATE INDEX schemas_changestreams_repository_id_idx ON schemas_changestreams(repository_id);

-- +goose StatementBegin
CREATE FUNCTION udf_audit_change_for_schemas()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO schemas_changestreams (operation, schema_id, created_at, updated_at, domains, account_id, repository_id)
        VALUES (TG_OP, OLD.schema_id, OLD.created_at, OLD.updated_at, OLD.domains, OLD.account_id, OLD.repository_id);
        RETURN OLD;
    ELSE
        INSERT INTO schemas_changestreams (operation, schema_id, created_at, updated_at, domains, account_id, repository_id)
        VALUES (TG_OP, NEW.schema_id, NEW.created_at, NEW.updated_at, NEW.domains, NEW.account_id, NEW.repository_id);
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE "plpgsql";
-- +goose StatementEnd

CREATE TRIGGER afr_iud_schemas_for_changestreams
	AFTER INSERT OR UPDATE OR DELETE ON schemas
	FOR EACH ROW EXECUTE FUNCTION udf_audit_change_for_schemas();

-- +goose Down
DROP FUNCTION IF EXISTS udf_audit_change_for_schemas CASCADE;
DROP TABLE IF EXISTS schemas_changestreams CASCADE;

DROP TABLE IF EXISTS schemas CASCADE;
