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
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/permguard/permguard/pkg/agents/runtime/mocks"
	"github.com/permguard/permguard/pkg/agents/storage"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
	csmocks "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/testutils/mocks"
)

// createSQLiteZAPCentralStorageWithMocks creates a new SQLiteCentralStorageZAP with mocks.
func createSQLiteZAPCentralStorageWithMocks() (*SQLiteCentralStorageZAP, *storage.StorageContext, *csmocks.MockSQLiteConnector, *csmocks.MockSqliteRepo, *csmocks.MockSqliteExecutor, *sqlx.DB, sqlmock.Sqlmock) {
	mockRuntimeCtx := mocks.NewRuntimeContextMock(nil, nil)
	mockStorageCtx, _ := storage.NewStorageContext(mockRuntimeCtx, storage.StorageSQLite)
	mockConnector := csmocks.NewMockSQLiteConnector()
	mockSQLRepo := csmocks.NewMockSqliteRepo()
	mockSQLExec := csmocks.NewMockSqliteExecutor()
	storage, _ := newSQLiteZAPCentralStorage(mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec)
	sqlDB, sqlMock, _ := sqlmock.New()
	sqlxDB := sqlx.NewDb(sqlDB, "sqlite3")
	return storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlxDB, sqlMock
}

// TestNewSQLiteZAPCentralStorage tests the newSQLiteZAPCentralStorage function.
func TestNewSQLiteZAPCentralStorage(t *testing.T) {
	assert := assert.New(t)
	storage, err := newSQLiteZAPCentralStorage(nil, nil, nil, nil)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientParameter, err), "error should be errclientparameter")
}
