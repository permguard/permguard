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
CREATE TABLE transactions (
    txid TEXT NOT NULL PRIMARY KEY,
    ledger_id TEXT NOT NULL,
    zone_id INTEGER NOT NULL REFERENCES zones(zone_id) ON UPDATE CASCADE ON DELETE CASCADE,
    started_at TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX transactions_status_started_idx ON transactions(status, started_at);
CREATE INDEX transactions_zoneid_idx ON transactions(zone_id);

ALTER TABLE key_values ADD COLUMN txid TEXT NOT NULL DEFAULT '';
ALTER TABLE ledgers ADD COLUMN txid TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE ledgers DROP COLUMN txid;
ALTER TABLE key_values DROP COLUMN txid;
DROP INDEX IF EXISTS transactions_status_started_idx;
DROP INDEX IF EXISTS transactions_zoneid_idx;
DROP TABLE IF EXISTS transactions;
