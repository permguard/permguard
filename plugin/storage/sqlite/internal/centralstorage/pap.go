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
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	azidb "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

// SQLiteCentralStoragePAP implements the sqlite central storage.
type SQLiteCentralStoragePAP struct {
	ctx             *azstorage.StorageContext
	sqliteConnector azidb.SQLiteConnector
	sqlRepo         SqliteRepo
	sqlExec         SqliteExecutor
	config          *SQLiteCentralStorageConfig
}

// newSQLitePAPCentralStorage creates a new SQLitePAPCentralStorage.
func newSQLitePAPCentralStorage(storageContext *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector, ledger SqliteRepo, sqlExec SqliteExecutor) (*SQLiteCentralStoragePAP, error) {
	if storageContext == nil || sqliteConnector == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, "storage: storageContext is nil")
	}
	if ledger == nil {
		ledger = &azirepos.Repository{}
	}
	if sqlExec == nil {
		sqlExec = &SqliteExec{}
	}
	config, err := NewSQLiteCentralStorageConfig(storageContext)
	if err != nil {
		return nil, err
	}
	return &SQLiteCentralStoragePAP{
		ctx:             storageContext,
		sqliteConnector: sqliteConnector,
		sqlRepo:         ledger,
		sqlExec:         sqlExec,
		config:          config,
	}, nil
}
