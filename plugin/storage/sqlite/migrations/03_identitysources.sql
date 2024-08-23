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
CREATE TABLE identity_sources (
    identity_source_id TEXT NOT NULL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    updated_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    name TEXT NOT NULL,
	-- REFERENCES
	account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT identity_sources_accountid_name_key UNIQUE (account_id, name)
);

CREATE INDEX identity_sources_name_idx ON identity_sources(name);
CREATE INDEX identity_sources_accountid_idx ON identity_sources(account_id);

-- Trigger to track changes in the `identity_sources` table after insert
-- +goose StatementBegin
CREATE TRIGGER identity_sources_change_streams_after_insert
AFTER INSERT ON identity_sources
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, account_id, payload)
		VALUES ('IDENTITY-SOURCE', 'INSERT', NEW.identity_source_id, NEW.account_id,
				'{"identity_source_id": "' || NEW.identity_source_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name || '", "account_id": ' || NEW.account_id || '}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `identity_sources` table after update
-- +goose StatementBegin
CREATE TRIGGER identity_sources_change_streams_after_update
AFTER UPDATE ON identity_sources
FOR EACH ROW
BEGIN
    UPDATE identity_sources SET updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE identity_source_id = OLD.identity_source_id;
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, account_id, payload)
		VALUES ('IDENTITY-SOURCE', 'UPDATE', NEW.identity_source_id, NEW.account_id,
				'{"identity_source_id": "' || NEW.identity_source_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name || '", "account_id": ' || NEW.account_id || '}');

END;
-- +goose StatementEnd

-- Trigger to track changes in the `identity_sources` table after delete
-- +goose StatementBegin
CREATE TRIGGER identity_sources_change_streams_after_delete
AFTER DELETE ON identity_sources
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, account_id, payload)
		VALUES ('IDENTITY-SOURCE', 'DELETE', OLD.identity_source_id, OLD.account_id,
				'{"identity_source_id": "' || OLD.identity_source_id || '", "created_at": "' || OLD.created_at ||
				'", "updated_at": "' || OLD.updated_at || '", "name": "' || OLD.name || '", "account_id": ' || OLD.account_id || '}');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS identity_sources_change_streams_after_insert;
DROP TRIGGER IF EXISTS identity_sources_change_streams_after_update;
DROP TRIGGER IF EXISTS identity_sources_change_streams_after_delete;
DROP TABLE IF EXISTS identity_sources;
