// Copyright 2024 Nitro Agility S.r.l.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package repositories

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// UpsertKeyValue creates or updates a key-value pair.
func (r *Repository) UpsertKeyValue(tx *sql.Tx, keyValue *KeyValue) (*KeyValue, error) {
	if keyValue == nil {
		return nil, errors.New("storage: invalid client input - key-value data is missing or malformed")
	}
	if keyValue.ZoneID <= 0 {
		return nil, errors.New("storage: invalid client input - zone id is missing or empty")
	}
	if keyValue.Key == "" {
		return nil, errors.New("storage: invalid client input - key is missing or empty")
	}

	zoneID := keyValue.ZoneID
	key := keyValue.Key
	value := keyValue.Value
	var result sql.Result
	var err error

	result, err = tx.Exec(`
		INSERT INTO key_values (zone_id, kv_key, kv_value)
		VALUES (?, ?, ?)
		ON CONFLICT(zone_id, kv_key)
		DO UPDATE SET kv_value = excluded.kv_value`,
		zoneID, key, value,
	)

	if err != nil || result == nil {
		params := map[string]string{WrapSqlite3ParamForeignKey: "key"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to upsert key-value pair - operation 'upsert-key-value' encountered an issue (key: %s)", key), err, params)
	}

	var dbKeyValue KeyValue
	err = tx.QueryRow("SELECT zone_id, kv_key, kv_value FROM key_values WHERE zone_id = ? and kv_key = ?", zoneID, key).Scan(
		&dbKeyValue.ZoneID,
		&dbKeyValue.Key,
		&dbKeyValue.Value,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve key-value pair - operation 'retrieve-upserted-key-value' encountered an issue (key: %s)", key), err)
	}
	return &dbKeyValue, nil
}

// GetKeyValue retrieves the value for a given key from the key-value store.
func (r *Repository) GetKeyValue(db *sqlx.DB, zoneID int64, key string) (*KeyValue, error) {
	if key == "" {
		return nil, errors.New("storage: invalid client input - key is missing or empty")
	}

	var dbKeyValue KeyValue
	err := db.QueryRow("SELECT zone_id, kv_key, kv_value FROM key_values WHERE zone_id = ? and kv_key = ?", zoneID, key).Scan(
		&dbKeyValue.ZoneID,
		&dbKeyValue.Key,
		&dbKeyValue.Value,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.Join(err, fmt.Errorf("no value found for key (%s)", key))
		}
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve key-value pair - operation 'retrieve-key-value' encountered an issue (key: %s)", key), err)
	}

	return &dbKeyValue, nil
}
