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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// TestCreateAccountWithInvalidInputs tests the CreateAccount function with invalid inputs.
func TestCreateAccountWithInvalidInputs(t *testing.T) {
	assert := assert.New(t)
	storage, _, _, _, _ := createSQLiteAAPCentralStorageWithMocks()
	accounts, err := storage.CreateAccount(nil)
	assert.Nil(accounts, "accounts should be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
}

// TestCreateAccountWithExecuteWithTransactionError tests the CreateAccount function with ExecuteWithTransaction error.
func TestCreateAccountWithExecuteWithTransactionError(t *testing.T) {
	assert := assert.New(t)
	storage, storageCtx, mockConnector, _, mockSQLExec := createSQLiteAAPCentralStorageWithMocks()

	errMsg := "ExecuteWithTransaction error"
	mockSQLExec.On("ExecuteWithTransaction", storageCtx, mockConnector, mock.Anything).Return(nil, errors.New(errMsg))

	accounts, err := storage.CreateAccount(&azmodels.Account{})
	assert.Nil(accounts, "accounts should be nil")
	assert.EqualError(err,errMsg)
}

// TestCreateAccountWithUpsertAccountError tests the CreateAccount function with UpsertAccount error.
func TestCreateAccountWithUpsertAccountError(t *testing.T) {
	assert := assert.New(t)
	storage, storageCtx, mockConnector, mockSQLRepo, mockSQLExec := createSQLiteAAPCentralStorageWithMocks()

	mockSQLExec.On("ExecuteWithTransaction", storageCtx, mockConnector, mock.Anything).Return(nil, nil).Run(func(args mock.Arguments) {
		execFunc := args.Get(2).(func(tx *sql.Tx) (interface{}, error))
		execFunc(nil)
	}).Once()

	errMsg := "UpsertAccount error"
	mockSQLRepo.On("UpsertAccount", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	accounts, err := storage.CreateAccount(&azmodels.Account{})
	assert.Nil(accounts, "accounts should be nil")
	assert.EqualError(err,errMsg)
}
