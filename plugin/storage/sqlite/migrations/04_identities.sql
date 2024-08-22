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
    identity_id TEXT NOT NULL PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    name TEXT NOT NULL UNIQUE,
	kind INTEGER NOT NULL,
	-- REFERENCES
	account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	identity_source_id TEXT NOT NULL REFERENCES identity_sources(identity_source_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT identities_accountid_name_key UNIQUE (account_id, name)
);

CREATE INDEX identities_name_idx ON identities(name);
CREATE INDEX identities_account_id_idx ON identities(account_id);
CREATE INDEX identities_identity_source_id_idx ON identities(identity_source_id);

-- Creating the `identity_changestreams` table
CREATE TABLE identity_changestreams (
    changestream_id INTEGER NOT NULL PRIMARY KEY,
	change_type TEXT NOT NULL,
	change_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    identity_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    name TEXT NOT NULL,
	kind INTEGER NOT NULL,
	-- REFERENCES
	account_id INTEGER NOT NULL,
	identity_source_id TEXT NOT NULL
);

CREATE INDEX identity_changestreams_name_idx ON identity_changestreams(name);
CREATE INDEX identity_changestreams_account_id_idx ON identity_changestreams(account_id);
CREATE INDEX identity_changestreams_identity_source_id_idx ON identity_changestreams(identity_source_id);


-- Trigger to track changes in the `identities` table after insert
-- +goose StatementBegin
CREATE TRIGGER identity_changestreams_after_insert
AFTER INSERT ON identities
FOR EACH ROW
BEGIN
    INSERT INTO identity_changestreams (change_type, identity_id, created_at, updated_at, name, kind, account_id, identity_source_id)
    	VALUES ('INSERT', NEW.identity_id, NEW.created_at, NEW.updated_at, NEW.name, NEW.kind, NEW.account_id, NEW.identity_source_id);
END;
-- +goose StatementEnd

-- Trigger to track changes in the `identities` table after update
-- +goose StatementBegin
CREATE TRIGGER identity_changestreams_after_update
AFTER UPDATE ON identities
FOR EACH ROW
BEGIN
    UPDATE identities SET updated_at = CURRENT_TIMESTAMP WHERE identity_id = OLD.identity_id;
    INSERT INTO identity_changestreams (change_type, identity_id, created_at, updated_at, name, kind, account_id, identity_source_id)
	    VALUES ('UPDATE', NEW.identity_id, NEW.created_at,CURRENT_TIMESTAMP, NEW.name, NEW.kind, NEW.account_id, NEW.identity_source_id);
END;
-- +goose StatementEnd

-- Trigger to track changes in the `identities` table after delete
-- +goose StatementBegin
CREATE TRIGGER identity_changestreams_after_delete
AFTER DELETE ON identities
FOR EACH ROW
BEGIN
    INSERT INTO identity_changestreams (change_type, identity_id, created_at, updated_at, name, kind, account_id, identity_source_id)
    	VALUES ('DELETE', OLD.identity_id, OLD.created_at, OLD.updated_at, OLD.name, OLD.kind, OLD.account_id, OLD.identity_source_id);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS identity_changestreams_after_insert;
DROP TRIGGER IF EXISTS identity_changestreams_after_update;
DROP TRIGGER IF EXISTS identity_changestreams_after_delete;
DROP TABLE IF EXISTS identity_changestreams;
DROP TABLE IF EXISTS identities;
