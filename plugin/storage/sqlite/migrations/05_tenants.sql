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
    tenant_id TEXT PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    name TEXT NOT NULL UNIQUE,
	-- REFERENCES
	account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT tenants_accountid_name_key UNIQUE (account_id, name)
);

CREATE INDEX tenants_name_idx ON tenants(name);
CREATE INDEX tenants_accountid_idx ON tenants(account_id);

-- Creating the `tenant_changestreams` table
CREATE TABLE tenant_changestreams (
    changestream_id TEXT PRIMARY KEY,
	change_type TEXT NOT NULL,
	change_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name TEXT NOT NULL,
	-- REFERENCES
	account_id INTEGER NOT NULL
);

CREATE INDEX tenant_changestreams_name_idx ON tenant_changestreams(name);
CREATE INDEX tenant_changestreams_accountid_idx ON tenant_changestreams(account_id);

-- Trigger to track changes in the `tenants` table after insert
-- +goose StatementBegin
CREATE TRIGGER tenant_changestreams_after_insert
AFTER INSERT ON tenants
FOR EACH ROW
BEGIN
    INSERT INTO tenant_changestreams (operation, tenant_id, created_at, updated_at, name, account_id)
    	VALUES ("INSERT", NEW.tenant_id, NEW.created_at, NEW.updated_at, NEW.name, NEW.account_id);
END;
-- +goose StatementEnd

-- Trigger to track changes in the `tenants` table after update
-- +goose StatementBegin
CREATE TRIGGER tenant_changestreams_after_update
AFTER UPDATE ON tenants
FOR EACH ROW
BEGIN
    UPDATE tenants SET updated_at = CURRENT_TIMESTAMP WHERE tenant_id = OLD.tenant_id;
    INSERT INTO tenant_changestreams (operation, tenant_id, created_at, updated_at, name, account_id)
	    VALUES ("UPDATE", COALESCE(NEW.tenant_id, OLD.tenant_id), COALESCE(NEW.created_at, OLD.created_at)
				,CURRENT_TIMESTAMP, COALESCE(NEW.name, OLD.name), COALESCE(NEW.account_id, OLD.account_id));
END;
-- +goose StatementEnd

-- Trigger to track changes in the `tenants` table after delete
-- +goose StatementBegin
CREATE TRIGGER tenant_changestreams_after_delete
AFTER DELETE ON tenants
FOR EACH ROW
BEGIN
    INSERT INTO tenant_changestreams (operation, tenant_id, created_at, updated_at, name, account_id)
    	VALUES ("DELETE", OLD.tenant_id, OLD.created_at, OLD.updated_at, OLD.name, OLD.account_id);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS tenant_changestreams_after_insert;
DROP TRIGGER IF EXISTS tenant_changestreams_after_update;
DROP TRIGGER IF EXISTS tenant_changestreams_after_delete;
DROP TABLE IF EXISTS tenant_changestreams;
DROP TABLE IF EXISTS tenants;
