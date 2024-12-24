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
CREATE TABLE ledgers (
    ledger_id TEXT NOT NULL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    updated_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    name TEXT NOT NULL,
	ref  TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
	-- REFERENCES
	application_id INTEGER NOT NULL REFERENCES applications(application_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT ledgers_applicationid_name_key UNIQUE (application_id, name)
);

CREATE INDEX ledgers_name_idx ON ledgers(name);
CREATE INDEX ledgers_applicationid_idx ON ledgers(application_id);

-- Trigger to track changes in the `ledgers` table after insert
-- +goose StatementBegin
CREATE TRIGGER ledgers_change_streams_after_insert
AFTER INSERT ON ledgers
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, application_id, payload)
		VALUES ('LEDGER', 'INSERT', NEW.ledger_id, NEW.application_id,
				'{"ledger_id": "' || NEW.ledger_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name ||
				'", "application_id": ' || NEW.application_id || ', "ref": "' || NEW.ref || '"}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `ledgers` table after update
-- +goose StatementBegin
CREATE TRIGGER ledgers_change_streams_after_update
AFTER UPDATE ON ledgers
FOR EACH ROW
BEGIN
    UPDATE ledgers SET updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE ledger_id = OLD.ledger_id;
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, application_id, payload)
		VALUES ('LEDGER', 'UPDATE', NEW.ledger_id, NEW.application_id,
				'{"ledger_id": "' || NEW.ledger_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name ||
				'", "application_id": ' || NEW.application_id || ', "ref": "' || NEW.ref || '"}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `ledgers` table after delete
-- +goose StatementBegin
CREATE TRIGGER ledgers_change_streams_after_delete
AFTER DELETE ON ledgers
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, application_id, payload)
		VALUES ('LEDGER', 'DELETE', OLD.ledger_id, OLD.application_id,
				'{"ledger_id": "' || OLD.ledger_id || '", "created_at": "' || OLD.created_at ||
				'", "updated_at": "' || OLD.updated_at || '", "name": "' || OLD.name ||
				'", "application_id": ' || OLD.application_id || ', "ref": "' || OLD.ref || '"}');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS ledgers_change_streams_after_insert;
DROP TRIGGER IF EXISTS ledgers_change_streams_after_update;
DROP TRIGGER IF EXISTS ledgers_change_streams_after_delete;
DROP TABLE IF EXISTS ledgers;
