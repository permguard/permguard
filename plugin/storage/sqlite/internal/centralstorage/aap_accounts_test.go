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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// TestNewSQLiteAAPCentralStorage tests the newSQLiteAAPCentralStorage function.
func TestCreateAccountWithError(t *testing.T) {
	assert := assert.New(t)

	storage, storageCtx, mockConnector, _, mockSQLExec := createSQLiteAAPCentralStorageWithMocks()

	mockSQLExec.On("ExecuteWithTransaction", storageCtx, mockConnector, mock.Anything).Return(nil, fmt.Errorf("error"))

	account:=  &azmodels.Account{}
	accounts, err := storage.CreateAccount(account)
	assert.Nil(accounts, "accounts should be nil")
	assert.NotNil(err, "error should not be nil")
}
