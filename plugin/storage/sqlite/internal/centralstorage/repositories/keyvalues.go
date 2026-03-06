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
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // SQLite driver

	storage "github.com/permguard/permguard/pkg/agents/storage"
)

// UpsertKeyValue creates or updates a key-value pair.
func (r *Repository) UpsertKeyValue(ctx context.Context, tx *sql.Tx, keyValue *KeyValue) (*KeyValue, error) {
	if keyValue == nil {
		return nil, fmt.Errorf("storage: invalid client input - key-value data is missing or malformed: %w", storage.ErrInvalidInput)
	}
	if keyValue.ZoneID <= 0 {
		return nil, fmt.Errorf("storage: invalid client input - zone id is missing or empty: %w", storage.ErrInvalidInput)
	}
	if keyValue.Key == "" {
		return nil, fmt.Errorf("storage: invalid client input - key is missing or empty: %w", storage.ErrInvalidInput)
	}

	zoneID := keyValue.ZoneID
	key := keyValue.Key
	value := keyValue.Value
	var result sql.Result
	var err error

	result, err = tx.ExecContext(ctx, `
		INSERT INTO key_values (zone_id, kv_key, kv_value)
		VALUES (?, ?, ?)
		ON CONFLICT(zone_id, kv_key)
		DO UPDATE SET kv_value = excluded.kv_value`,
		zoneID, key, value,
	)

	if err != nil || result == nil {
		params := map[string]string{WrapSqliteParamForeignKey: "key"}
		return nil, WrapSqliteErrorWithParams(fmt.Sprintf("failed to upsert key-value pair - operation 'upsert-key-value' encountered an issue (key: %s)", key), err, params)
	}

	var dbKeyValue KeyValue
	err = tx.QueryRowContext(ctx, "SELECT zone_id, kv_key, kv_value FROM key_values WHERE zone_id = ? and kv_key = ?", zoneID, key).Scan(
		&dbKeyValue.ZoneID,
		&dbKeyValue.Key,
		&dbKeyValue.Value,
	)
	if err != nil {
		return nil, WrapSqliteError(fmt.Sprintf("failed to retrieve key-value pair - operation 'retrieve-upserted-key-value' encountered an issue (key: %s)", key), err)
	}
	return &dbKeyValue, nil
}

// KeyValue retrieves the value for a given key from the key-value store.
func (r *Repository) KeyValue(ctx context.Context, db *sqlx.DB, zoneID int64, key string) (*KeyValue, error) {
	if key == "" {
		return nil, fmt.Errorf("storage: invalid client input - key is missing or empty: %w", storage.ErrInvalidInput)
	}

	var dbKeyValue KeyValue
	err := db.QueryRowContext(ctx, "SELECT zone_id, kv_key, kv_value FROM key_values WHERE zone_id = ? and kv_key = ?", zoneID, key).Scan(
		&dbKeyValue.ZoneID,
		&dbKeyValue.Key,
		&dbKeyValue.Value,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no value found for key (%s): %w", key, storage.ErrNotFound)
		}
		return nil, WrapSqliteError(fmt.Sprintf("failed to retrieve key-value pair - operation 'retrieve-key-value' encountered an issue (key: %s)", key), err)
	}

	return &dbKeyValue, nil
}
