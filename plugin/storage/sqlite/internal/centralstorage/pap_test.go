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

	azrtmmocks "github.com/permguard/permguard/pkg/agents/runtime/mocks"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmocks "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/testutils/mocks"
)

// createSQLitePAPCentralStorageWithMocks creates a new SQLiteCentralStoragePAP with mocks.
func createSQLitePAPCentralStorageWithMocks() (*SQLiteCentralStoragePAP, *azstorage.StorageContext, *azmocks.MockSQLiteConnector, *azmocks.MockSqliteRepo, *azmocks.MockSqliteExecutor, *sqlx.DB, sqlmock.Sqlmock) {
	mockRuntimeCtx := azrtmmocks.NewRuntimeContextMock(nil, nil)
	mockStorageCtx, _ := azstorage.NewStorageContext(mockRuntimeCtx, azstorage.StorageSQLite)
	mockConnector := azmocks.NewMockSQLiteConnector()
	mockSQLRepo := azmocks.NewMockSqliteRepo()
	mockSQLExec := azmocks.NewMockSqliteExecutor()
	storage, _ := newSQLitePAPCentralStorage(mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec)
	sqlDB, sqlMock, _ := sqlmock.New()
	sqlxDB := sqlx.NewDb(sqlDB, "sqlite3")
	return storage, mockStorageCtx, mockConnector, mockSQLRepo, mockSQLExec, sqlxDB, sqlMock
}

// TestNewSQLitePAPCentralStorage tests the newSQLitePAPCentralStorage function.
func TestNewSQLitePAPCentralStorage(t *testing.T) {
	assert := assert.New(t)
	storage, err := newSQLitePAPCentralStorage(nil, nil, nil, nil)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
}
