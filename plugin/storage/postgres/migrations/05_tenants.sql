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
CREATE TABLE tenants (
    tenant_id UUID PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    name VARCHAR(254) NOT NULL,
	-- REFERENCES
	account_id BIGINT NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT tenants_accountid_name_key UNIQUE (account_id, name)
);

CREATE INDEX tenants_name_idx ON tenants(name);
CREATE INDEX tenants_account_id_idx ON tenants(account_id);

CREATE TRIGGER bfr_u_tenants
	BEFORE UPDATE ON tenants
	FOR EACH ROW EXECUTE FUNCTION udf_row_update_timestamp();

-- +goose Down
DROP TRIGGER IF EXISTS bfr_u_tenants ON tenants;
DROP TABLE IF EXISTS tenants CASCADE;
