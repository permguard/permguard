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

CREATE TABLE tenants_changestreams (
    changestream_id SERIAL PRIMARY KEY NOT NULL,
	operation VARCHAR(10) NOT NULL,
	operation_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    tenant_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    name VARCHAR(254) NOT NULL,
	-- REFERENCES
	account_id BIGINT NOT NULL
);

CREATE INDEX tenants_changestreams_name_idx ON tenants_changestreams(name);
CREATE INDEX tenants_changestreams_account_id_idx ON tenants_changestreams(account_id);

-- +goose StatementBegin
CREATE FUNCTION udf_audit_change_for_tenants()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO tenants_changestreams (operation, tenant_id, created_at, updated_at, name, account_id)
        VALUES (TG_OP, OLD.tenant_id, OLD.created_at, OLD.updated_at, OLD.name, OLD.account_id);
        RETURN OLD;
    ELSE
        INSERT INTO tenants_changestreams (operation, tenant_id, created_at, updated_at, name, account_id)
        VALUES (TG_OP, NEW.tenant_id, NEW.created_at, NEW.updated_at, NEW.name, NEW.account_id);
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE "plpgsql";
-- +goose StatementEnd

CREATE TRIGGER afr_iud_tenants_for_changestreams
	AFTER INSERT OR UPDATE OR DELETE ON tenants
	FOR EACH ROW EXECUTE FUNCTION udf_audit_change_for_tenants();

-- +goose Down
DROP FUNCTION IF EXISTS udf_audit_change_for_tenants CASCADE;
DROP TABLE IF EXISTS tenants_changestreams CASCADE;

DROP TABLE IF EXISTS tenants CASCADE;
