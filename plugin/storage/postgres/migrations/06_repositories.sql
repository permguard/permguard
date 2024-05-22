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
CREATE TABLE repositories (
    repository_id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    name VARCHAR(254) NOT NULL,
	-- REFERENCES
	account_id BIGINT NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT repositories_accountid_name_key UNIQUE (account_id, name)
);

CREATE INDEX repositories_name_idx ON repositories(name);
CREATE INDEX repositories_account_id_idx ON repositories(account_id);

CREATE TRIGGER bfr_u_repositories
	BEFORE UPDATE ON repositories
	FOR EACH ROW EXECUTE FUNCTION udf_row_update_timestamp();

CREATE TABLE repositories_changestreams (
    changestream_id SERIAL PRIMARY KEY NOT NULL,
	operation VARCHAR(10) NOT NULL,
	operation_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    repository_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    name VARCHAR(254) NOT NULL,
	-- REFERENCES
	account_id BIGINT NOT NULL
);

CREATE INDEX repositories_changestreams_name_idx ON repositories_changestreams(name);
CREATE INDEX repositories_changestreams_account_id_idx ON repositories_changestreams(account_id);

-- +goose StatementBegin
CREATE FUNCTION udf_audit_change_for_repositories()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO repositories_changestreams (operation, repository_id, created_at, updated_at, name, account_id)
        VALUES (TG_OP, OLD.repository_id, OLD.created_at, OLD.updated_at, OLD.name, OLD.account_id);
        RETURN OLD;
    ELSE
        INSERT INTO repositories_changestreams (operation, repository_id, created_at, updated_at, name, account_id)
        VALUES (TG_OP, NEW.repository_id, NEW.created_at, NEW.updated_at, NEW.name, NEW.account_id);
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE "plpgsql";
-- +goose StatementEnd

CREATE TRIGGER afr_iud_repositories_for_changestreams
	AFTER INSERT OR UPDATE OR DELETE ON repositories
	FOR EACH ROW EXECUTE FUNCTION udf_audit_change_for_repositories();

-- +goose Down
DROP FUNCTION IF EXISTS udf_audit_change_for_repositories CASCADE;
DROP TABLE IF EXISTS repositories_changestreams CASCADE;

DROP TABLE IF EXISTS repositories CASCADE;
