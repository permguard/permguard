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

	azrtmmocks "github.com/permguard/permguard/pkg/agents/runtime/mocks"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azmocks "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/testutils/mocks"
)

// TestNewSQLiteAAPCentralStorage tests the newSQLiteAAPCentralStorage function.
func TestCreateAccountWithError(t *testing.T) {
	assert := assert.New(t)
	runtimeCtx := azrtmmocks.NewRuntimeContextMock()
	storageCtx, err := azstorage.NewStorageContext(runtimeCtx, azstorage.StorageSQLite)
	if err != nil {
		t.Fatal(err)
	}
	mockConnector, _ := azmocks.NewMockSQLiteConnector()
	storage, _ := newSQLiteAAPCentralStorage(storageCtx, mockConnector, nil)
	assert.NotNil(storage, "storage should be nil")
}
