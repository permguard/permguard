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
CREATE TABLE keyvalues (
    key TEXT NOT NULL PRIMARY KEY,
    value BLOB NOT NULL
);

-- Creating the `change_streams` table
CREATE TABLE change_streams (
    changestream_id INTEGER NOT NULL PRIMARY KEY,
	change_entity TEXT NOT NULL,
	change_type TEXT NOT NULL,
	change_entity_id TEXT,
	change_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    account_id INTEGER NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX change_streams_change_entity_idx ON change_streams(change_entity);
CREATE INDEX change_streams_change_type_idx ON change_streams(change_type);
CREATE INDEX change_streams_change_entity_id_idx ON change_streams(change_entity_id);
CREATE INDEX change_streams_account_id_idx ON change_streams(account_id);
CREATE INDEX change_streams_change_at_idx ON change_streams(change_at);

-- +goose Down
DROP TABLE IF EXISTS change_streams;
DROP TABLE IF EXISTS keyvalues;
