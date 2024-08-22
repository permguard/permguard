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
	"github.com/jmoiron/sqlx"
	
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	azidb "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
)

// SqliteExecutor is the interface for executing sqlite commands.
type SqliteExecutor interface {
	// Connect connects to the sqlite database.
	Connect(ctx *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector) (*sqlx.DB, error)
}

// SqliteExec implements the SqliteExecutor interface.
type SqliteExec struct {
}

// Connect connects to the sqlite database.
func (s SqliteExec) Connect(ctx *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector) (*sqlx.DB, error) {
	logger := ctx.GetLogger()
	db, err := sqliteConnector.Connect(logger, ctx)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error("cannot connect to sqlite.", err)
	}
	return db, nil
}

// SQLiteCentralStorage implements the sqlite central storage.
type SQLiteCentralStorage struct {
	ctx             *azstorage.StorageContext
	sqliteConnector azidb.SQLiteConnector
}

// NewSQLiteCentralStorage creates a new sqlite central storage.
func NewSQLiteCentralStorage(storageContext *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector) (*SQLiteCentralStorage, error) {
	return &SQLiteCentralStorage{
		ctx:             storageContext,
		sqliteConnector: sqliteConnector,
	}, nil
}

// GetAAPCentralStorage returns the AAP central storage.
func (s SQLiteCentralStorage) GetAAPCentralStorage() (azstorage.AAPCentralStorage, error) {
	return newSQLiteAAPCentralStorage(s.ctx, s.sqliteConnector, nil, nil)
}

// GetPAPCentralStorage returns the PAP central storage.
func (s SQLiteCentralStorage) GetPAPCentralStorage() (azstorage.PAPCentralStorage, error) {
	return nil, nil //TODO: azerrors.WrapSystemError(azerrors.ErrNotImplemented, "storage: pap central storage has not been implemented by the sqlite plugin.")
}
