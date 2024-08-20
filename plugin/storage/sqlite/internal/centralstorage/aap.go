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
	"database/sql"

	"github.com/jmoiron/sqlx"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	azidb "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

type SqliteRepo interface {
	UpsertAccount(tx *sql.Tx, isCreate bool, account *azrepos.Account) (*azrepos.Account, error)
	DeleteAccount(tx *sql.Tx, accountID int64) (*azrepos.Account, error)
	FetchAccounts(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azrepos.Account, error)
}

// SQLiteCentralStorageAAP implements the sqlite central storage.
type SQLiteCentralStorageAAP struct {
	ctx             *azstorage.StorageContext
	sqliteConnector azidb.SQLiteConnector
	sqlRepo         SqliteRepo
	sqlExec         SqliteExecutor
}

// newSQLiteAAPCentralStorage creates a new SQLiteAAPCentralStorage.
func newSQLiteAAPCentralStorage(storageContext *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector, repo SqliteRepo, sqlExec SqliteExecutor) (*SQLiteCentralStorageAAP, error) {
	if storageContext == nil || sqliteConnector == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: storageContext is nil.")
	}
	if repo == nil {
		repo = &azrepos.Repo{}
	}
	if sqlExec == nil {
		sqlExec = &SqliteExec{}
	}
	return &SQLiteCentralStorageAAP{
		ctx:             storageContext,
		sqliteConnector: sqliteConnector,
		sqlRepo:         repo,
		sqlExec:         sqlExec,
	}, nil
}
