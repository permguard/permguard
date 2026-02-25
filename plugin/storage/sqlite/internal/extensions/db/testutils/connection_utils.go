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

package testutils

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	mock "github.com/stretchr/testify/mock"

	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db/testutils/mocks"
)

// NewSqliteConnectionMocks creates mocks for the SQLite connection.
func NewSqliteConnectionMocks(t *testing.T) (db.SQLiteConnector, *sqlx.DB, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, sqlMock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	sqlxDB := sqlx.NewDb(sqlDB, "sqlite")

	if err != nil {
		t.Fatal(err)
	}
	sqlConnMock := mocks.NewSQLiteConnectionMock()
	sqlConnMock.On("Storage").Return(storage.StorageSQLite)
	sqlConnMock.On("Connect", mock.Anything, mock.Anything).Return(sqlxDB, nil)
	sqlConnMock.On("Close", sqlxDB).Return(nil)
	return sqlConnMock, sqlxDB, sqlMock
}
