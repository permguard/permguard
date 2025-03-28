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
    created_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    updated_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    name TEXT NOT NULL,
	kind INTEGER NOT NULL,
	-- REFERENCES
	zone_id INTEGER NOT NULL REFERENCES zones(zone_id) ON UPDATE CASCADE ON DELETE CASCADE,
	identity_source_id TEXT NOT NULL REFERENCES identity_sources(identity_source_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT identities_zoneid_name_key UNIQUE (zone_id, name)
);

CREATE INDEX identities_name_idx ON identities(name);
CREATE INDEX identities_zone_id_idx ON identities(zone_id);
CREATE INDEX identities_identity_source_id_idx ON identities(identity_source_id);

-- Trigger to track changes in the `identities` table after insert
-- +goose StatementBegin
CREATE TRIGGER change_streams_after_insert
AFTER INSERT ON identities
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('IDENTITY', 'INSERT', NEW.identity_id, NEW.zone_id,
				'{"identity_id": "' || NEW.identity_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name ||
				'", "kind": ' || NEW.kind || ', "zone_id": ' || NEW.zone_id ||
				', "identity_source_id": "' || NEW.identity_source_id || '"}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `identities` table after update
-- +goose StatementBegin
CREATE TRIGGER change_streams_after_update
AFTER UPDATE ON identities
FOR EACH ROW
BEGIN
    UPDATE identities SET updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE identity_id = OLD.identity_id;
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('IDENTITY', 'UPDATE', NEW.identity_id, NEW.zone_id,
				'{"identity_id": "' || NEW.identity_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name ||
				'", "kind": ' || NEW.kind || ', "zone_id": ' || NEW.zone_id ||
				', "identity_source_id": "' || NEW.identity_source_id || '"}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `identities` table after delete
-- +goose StatementBegin
CREATE TRIGGER change_streams_after_delete
AFTER DELETE ON identities
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('IDENTITY', 'DELETE', OLD.identity_id, OLD.zone_id,
				'{"identity_id": "' || OLD.identity_id || '", "created_at": "' || OLD.created_at ||
				'", "updated_at": "' || OLD.updated_at || '", "name": "' || OLD.name ||
				'", "kind": ' || OLD.kind || ', "zone_id": ' || OLD.zone_id ||
				', "identity_source_id": "' || OLD.identity_source_id || '"}');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS change_streams_after_insert;
DROP TRIGGER IF EXISTS change_streams_after_update;
DROP TRIGGER IF EXISTS change_streams_after_delete;
DROP TABLE IF EXISTS identities;
