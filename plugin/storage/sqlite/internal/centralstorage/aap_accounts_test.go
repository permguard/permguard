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
	"github.com/stretchr/testify/assert"

	_ "github.com/mattn/go-sqlite3"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// TestAAPCreateAccountWithNil tests the creation of an account with a nil account.
func TestAAPCreateAccountWithInvalidName(t *testing.T) {
	assert := assert.New(t)

	tests := []string{
		"",
		" ",
		"@",
		"1aX",
		"X-@x"}
	for _, test := range tests {
		accountName := test
		storage, sqlDB, _, sqlMock := NewSqliteCentralStorageAAPMock(t)
		defer sqlDB.Close()

		sqlMock.ExpectBegin()

		account := &azmodels.Account{
			Name: accountName,
		}
		account, err := storage.CreateAccount(account)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be ErrClientParameter")
		assert.Nil(account, "accounts should be nil")
	}
}

func TestAAPCreateAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := NewSqliteCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, sqlAccountRows := registerAccountForInsertMocking()
	// account, accountsSQL, sqlAccounts := registerAccountForInsertMocking()

	mock.ExpectBegin()
    mock.ExpectExec(`INSERT INTO accounts \(account_id, name\) VALUES \(\?, \?\)`).
        WithArgs(sqlmock.AnyArg(), "rent-a-car").
        WillReturnResult(sqlmock.NewResult(1, 1))

    mock.ExpectQuery(`SELECT account_id, created_at, updated_at, name FROM accounts WHERE account_id = \?`).
        WithArgs(sqlmock.AnyArg()).
        WillReturnRows(sqlAccountRows)

	mock.ExpectCommit()

	inputAccount := &azmodels.Account{
		Name: account.Name,
	}
	outputAccount, err := storage.CreateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputAccount, "account should be not nil")
	assert.Equal(account.AccountID, outputAccount.AccountID, "account name is not correct")
	assert.Equal(account.Name, outputAccount.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}
