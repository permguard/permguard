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

package facade

import (
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// UpsertKeyValue creates or updates a key-value pair.
func (r *Facade) UpsertKeyValue(tx *sql.Tx, keyValue *KeyValue) (*KeyValue, error) {
	if keyValue == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - key-value data is missing or malformed")
	}
	if keyValue.Key == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - key is missing or empty")
	}

	key := keyValue.Key
	value := keyValue.Value
	var result sql.Result
	var err error

	result, err = tx.Exec(`
		INSERT INTO key_values (kv_key, kv_value)
		VALUES (?, ?)
		ON CONFLICT(kv_key)
		DO UPDATE SET kv_value = excluded.kv_value`,
		key, value,
	)

	if err != nil || result == nil {
		params := map[string]string{WrapSqlite3ParamForeignKey: "key"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to upsert key-value pair - operation 'upsert-key-value' encountered an issue (key: %s)", key), err, params)
	}

	var dbKeyValue KeyValue
	err = tx.QueryRow("SELECT kv_key, kv_value FROM key_values WHERE kv_key = ?", key).Scan(
		&dbKeyValue.Key,
		&dbKeyValue.Value,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve key-value pair - operation 'retrieve-upserted-key-value' encountered an issue (key: %s)", key), err)
	}
	return &dbKeyValue, nil
}

// GetKeyValue retrieves the value for a given key from the key-value store.
func (r *Facade) GetKeyValue(db *sqlx.DB, key string) (*KeyValue, error) {
	if key == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - key is missing or empty")
	}

	var dbKeyValue KeyValue
	err := db.QueryRow("SELECT kv_key, kv_value FROM key_values WHERE kv_key = ?", key).Scan(
		&dbKeyValue.Key,
		&dbKeyValue.Value,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageNotFound, fmt.Sprintf("storage: no value found for key (%s)", key))
		}
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve key-value pair - operation 'retrieve-key-value' encountered an issue (key: %s)", key), err)
	}

	return &dbKeyValue, nil
}
