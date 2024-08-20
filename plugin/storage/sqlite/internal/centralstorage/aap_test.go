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

	"github.com/stretchr/testify/assert"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azrtmmocks "github.com/permguard/permguard/pkg/agents/runtime/mocks"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azmocks "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/testutils/mocks"
)

// createSQLiteAAPCentralStorageWithMocks creates a new SQLiteCentralStorageAAP with mocks.
func createSQLiteAAPCentralStorageWithMocks() (*SQLiteCentralStorageAAP, *azstorage.StorageContext, *azmocks.MockSQLiteConnector, *azmocks.MockSqliteRepo, *azmocks.MockSqliteExecutor) {
	runtimeCtx := azrtmmocks.NewRuntimeContextMock()
	storageCtx, _ := azstorage.NewStorageContext(runtimeCtx, azstorage.StorageSQLite)
	mockConnector := azmocks.NewMockSQLiteConnector()
	mockSQLRepo := azmocks.NewMockSqliteRepo()
	mockSQLExec := azmocks.NewMockSqliteExecutor()

	storage, _ := newSQLiteAAPCentralStorage(storageCtx, mockConnector, mockSQLRepo, mockSQLExec)
	return storage, storageCtx, mockConnector, mockSQLRepo, mockSQLExec
}

// TestNewSQLiteAAPCentralStorage tests the newSQLiteAAPCentralStorage function.
func TestNewSQLiteAAPCentralStorage(t *testing.T) {
	assert := assert.New(t)
	storage, err := newSQLiteAAPCentralStorage(nil, nil, nil, nil)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
}
