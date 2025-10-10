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
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/permguard/permguard/pkg/agents/runtime/mocks"
	"github.com/permguard/permguard/pkg/agents/storage"
	testutilsmocks "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/testutils/mocks"
)

// TestSqliteExecutor tests the sqlite executor.
func TestSqliteExecutor(t *testing.T) {
	assert := assert.New(t)

	{
		mockRuntimeCtx := mocks.NewRuntimeContextMock(nil, nil)
		mockStorageCtx, _ := storage.NewStorageContext(mockRuntimeCtx, storage.StorageSQLite)
		mockConnector := testutilsmocks.NewMockSQLiteConnector()

		sqliteExec := &SqliteExec{}

		mockConnector.On("Connect", mock.Anything, mockStorageCtx).Return(nil, errors.New("operation error"))

		db, err := sqliteExec.Connect(mockStorageCtx, mockConnector)
		assert.Nil(db, "db should be nil")
		assert.NotNil(err, "error should not be nil")
	}

	{
		mockRuntimeCtx := mocks.NewRuntimeContextMock(nil, nil)
		mockStorageCtx, _ := storage.NewStorageContext(mockRuntimeCtx, storage.StorageSQLite)
		mockConnector := testutilsmocks.NewMockSQLiteConnector()

		sqlDB, _, _ := sqlmock.New()
		sqlxDB := sqlx.NewDb(sqlDB, "sqlite")

		sqliteExec := &SqliteExec{}

		mockConnector.On("Connect", mock.Anything, mockStorageCtx).Return(sqlxDB, nil)

		db, err := sqliteExec.Connect(mockStorageCtx, mockConnector)
		assert.NotNil(db, "db should be nil")
		assert.Equal(sqlxDB, db, "db should be equal")
		assert.Nil(err, "error should not be nil")
	}

}

// TestNewSQLiteCentralStorage tests the new sqlite central storage.
func TestNewSQLiteCentralStorage(t *testing.T) {
	assert := assert.New(t)

	{
		mockRuntimeCtx := mocks.NewRuntimeContextMock(nil, nil)
		mockStorageCtx, _ := storage.NewStorageContext(mockRuntimeCtx, storage.StorageSQLite)
		mockConnector := testutilsmocks.NewMockSQLiteConnector()

		sqliteExec, err := NewSQLiteCentralStorage(mockStorageCtx, mockConnector)
		assert.Nil(err)

		zapcentralstorage, err := sqliteExec.ZAPCentralStorage()
		assert.NotNil(zapcentralstorage)
		assert.Nil(err)

		papcentralstorage, err := sqliteExec.PAPCentralStorage()
		assert.NotNil(papcentralstorage)
		assert.Nil(err)
	}

}
