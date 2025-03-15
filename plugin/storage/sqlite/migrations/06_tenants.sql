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
    tenant_id TEXT NOT NULL PRIMARY KEY,
    created_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    updated_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    name TEXT NOT NULL,
	-- REFERENCES
	zone_id INTEGER NOT NULL REFERENCES zones(zone_id) ON UPDATE CASCADE ON DELETE CASCADE,
	-- CONSTRAINTS
	CONSTRAINT tenants_zoneid_name_key UNIQUE (zone_id, name)
);

CREATE INDEX tenants_name_idx ON tenants(name);
CREATE INDEX tenants_zoneid_idx ON tenants(zone_id);

-- Trigger to track changes in the `tenants` table after insert
-- +goose StatementBegin
CREATE TRIGGER tenants_change_streams_after_insert
AFTER INSERT ON tenants
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('TENANT', 'INSERT', NEW.tenant_id, NEW.zone_id,
				'{"tenant_id": "' || NEW.tenant_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name ||
				'", "zone_id": ' || NEW.zone_id || '}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `tenants` table after update
-- +goose StatementBegin
CREATE TRIGGER tenants_change_streams_after_update
AFTER UPDATE ON tenants
FOR EACH ROW
BEGIN
    UPDATE tenants SET updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE tenant_id = OLD.tenant_id;
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('TENANT', 'UPDATE', NEW.tenant_id, NEW.zone_id,
				'{"tenant_id": "' || NEW.tenant_id || '", "created_at": "' || NEW.created_at ||
				'", "updated_at": "' || NEW.updated_at || '", "name": "' || NEW.name ||
				'", "zone_id": ' || NEW.zone_id || '}');
END;
-- +goose StatementEnd

-- Trigger to track changes in the `tenants` table after delete
-- +goose StatementBegin
CREATE TRIGGER tenants_change_streams_after_delete
AFTER DELETE ON tenants
FOR EACH ROW
BEGIN
    INSERT INTO change_streams (change_entity, change_type, change_entity_id, zone_id, payload)
		VALUES ('TENANT', 'DELETE', OLD.tenant_id, OLD.zone_id,
				'{"tenant_id": "' || OLD.tenant_id || '", "created_at": "' || OLD.created_at ||
				'", "updated_at": "' || OLD.updated_at || '", "name": "' || OLD.name ||
				'", "zone_id": ' || OLD.zone_id || '}');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS tenants_change_streams_after_insert;
DROP TRIGGER IF EXISTS tenants_change_streams_after_update;
DROP TRIGGER IF EXISTS tenants_change_streams_after_delete;
DROP TABLE IF EXISTS tenants;
