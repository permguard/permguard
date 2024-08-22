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
CREATE TABLE identitysources (
    identitysource_id TEXT PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    name TEXT NOT NULL UNIQUE,
	-- REFERENCES
	account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT identitysources_accountid_name_key UNIQUE (account_id, name)
);

CREATE INDEX identitysources_name_idx ON identitysources(name);
CREATE INDEX identitysources_accountid_idx ON identitysources(account_id);

-- Creating the `identitysource_changestreams` table
CREATE TABLE identitysource_changestreams (
    changestream_id TEXT PRIMARY KEY,
	change_type TEXT NOT NULL,
	change_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    identitysource_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name TEXT NOT NULL,
	-- REFERENCES
	account_id INTEGER NOT NULL
);

CREATE INDEX identitysource_changestreams_name_idx ON identitysource_changestreams(name);
CREATE INDEX identitysource_changestreams_accountid_idx ON identitysource_changestreams(account_id);

-- Trigger to track changes in the `identitysources` table after insert
-- +goose StatementBegin
CREATE TRIGGER identitysource_changestreams_after_insert
AFTER INSERT ON identitysources
FOR EACH ROW
BEGIN
    INSERT INTO identitysource_changestreams (change_type, identitysource_id, created_at, updated_at, name, account_id)
    	VALUES ('INSERT', NEW.identitysource_id, NEW.created_at, NEW.updated_at, NEW.name, NEW.account_id);
END;
-- +goose StatementEnd

-- Trigger to track changes in the `identitysources` table after update
-- +goose StatementBegin
CREATE TRIGGER identitysource_changestreams_after_update
AFTER UPDATE ON identitysources
FOR EACH ROW
BEGIN
    UPDATE identitysources SET updated_at = CURRENT_TIMESTAMP WHERE identitysource_id = OLD.identitysource_id;
    INSERT INTO identitysource_changestreams (change_type, identitysource_id, created_at, updated_at, name, account_id)
	    VALUES ('UPDATE', NEW.identitysource_id, NEW.created_at, CURRENT_TIMESTAMP, NEW.name, NEW.account_id);
END;
-- +goose StatementEnd

-- Trigger to track changes in the `identitysources` table after delete
-- +goose StatementBegin
CREATE TRIGGER identitysource_changestreams_after_delete
AFTER DELETE ON identitysources
FOR EACH ROW
BEGIN
    INSERT INTO identitysource_changestreams (change_type, identitysource_id, created_at, updated_at, name, account_id)
    	VALUES ('DELETE', OLD.identitysource_id, OLD.created_at, OLD.updated_at, OLD.name, OLD.account_id);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS identitysource_changestreams_after_insert;
DROP TRIGGER IF EXISTS identitysource_changestreams_after_update;
DROP TRIGGER IF EXISTS identitysource_changestreams_after_delete;
DROP TABLE IF EXISTS identitysource_changestreams;
DROP TABLE IF EXISTS identitysources;
