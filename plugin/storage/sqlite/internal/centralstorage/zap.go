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

package centralstorage

import (
	"errors"

	"github.com/permguard/permguard/pkg/agents/storage"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

// SQLiteCentralStorageZAP implements the sqlite central storage.
type SQLiteCentralStorageZAP struct {
	ctx             *storage.StorageContext
	sqliteConnector db.SQLiteConnector
	sqlRepo         SqliteRepo
	sqlExec         SqliteExecutor
	config          *SQLiteCentralStorageConfig
}

// newSQLiteZAPCentralStorage creates a new SQLiteZAPCentralStorage.
func newSQLiteZAPCentralStorage(storageContext *storage.StorageContext, sqliteConnector db.SQLiteConnector, ledger SqliteRepo, sqlExec SqliteExecutor) (*SQLiteCentralStorageZAP, error) {
	if storageContext == nil || sqliteConnector == nil {
		return nil, errors.New("storage: storageContext is nil")
	}
	if ledger == nil {
		ledger = &repos.Repository{}
	}
	if sqlExec == nil {
		sqlExec = &SqliteExec{}
	}
	config, err := NewSQLiteCentralStorageConfig(storageContext)
	if err != nil {
		return nil, err
	}
	return &SQLiteCentralStorageZAP{
		ctx:             storageContext,
		sqliteConnector: sqliteConnector,
		sqlRepo:         ledger,
		sqlExec:         sqlExec,
		config:          config,
	}, nil
}
