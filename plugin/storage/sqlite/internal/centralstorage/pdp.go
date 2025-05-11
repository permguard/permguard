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
	"github.com/permguard/permguard/pkg/agents/storage"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

// SQLiteCentralStoragePDP implements the sqlite central storage.
type SQLiteCentralStoragePDP struct {
	ctx             *storage.StorageContext
	sqliteConnector db.SQLiteConnector
	sqlRepo         SqliteRepo
	sqlExec         SqliteExecutor
	config          *SQLiteCentralStorageConfig
}

// newSQLitePDPCentralStorage creates a new SQLitePDPCentralStorage.
func newSQLitePDPCentralStorage(storageContext *storage.StorageContext, sqliteConnector db.SQLiteConnector, ledger SqliteRepo, sqlExec SqliteExecutor) (*SQLiteCentralStoragePDP, error) {
	if storageContext == nil || sqliteConnector == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, "storageContext is nil")
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
	return &SQLiteCentralStoragePDP{
		ctx:             storageContext,
		sqliteConnector: sqliteConnector,
		sqlRepo:         ledger,
		sqlExec:         sqlExec,
		config:          config,
	}, nil
}
