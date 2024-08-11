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

-- +goose Down
DROP TRIGGER IF EXISTS bfr_u_identities ON identities;
DROP TABLE IF EXISTS identities CASCADE;
