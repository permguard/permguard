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

-- +goose Down
DROP TRIGGER IF EXISTS bfr_u_schemas ON schemas;
DROP TABLE IF EXISTS schemas CASCADE;
