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
CREATE TABLE zones (
    zone_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    updated_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    name TEXT NOT NULL UNIQUE
);

CREATE INDEX zones_name_idx ON zones(name);

-- Trigger to track changes in the `zones` table after insert
-- +goose StatementBegin
CREATE TRIGGER zones_change_streams_after_insert
AFTER INSERT ON zones
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('ZONE', 'INSERT', NEW.zone_id, NEW.zone_id,
				'{"zone_id": ' || NEW.zone_id || ', "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name || '"}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `zones` table after update
-- +goose StatementBegin
CREATE TRIGGER zones_change_streams_after_update
AFTER UPDATE ON zones
FOR EACH ROW
BEGIN
    UPDATE zones SET updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE zone_id = OLD.zone_id;
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('ZONE', 'INSERT', NEW.zone_id, NEW.zone_id,
				'{"zone_id": ' || NEW.zone_id || ', "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name || '"}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `zones` table after delete
-- +goose StatementBegin
CREATE TRIGGER zones_change_streams_after_delete
AFTER DELETE ON zones
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('ZONE', 'DELETE', OLD.zone_id, OLD.zone_id,
				'{"zone_id": ' || OLD.zone_id || ', "created_at": "' || OLD.created_at ||
				'", "updated_at": "' || OLD.updated_at || '", "name": "' || OLD.name || '""}');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS zones_change_streams_after_insert;
DROP TRIGGER IF EXISTS zones_change_streams_after_update;
DROP TRIGGER IF EXISTS zones_change_streams_after_delete;
DROP TABLE IF EXISTS zones;
