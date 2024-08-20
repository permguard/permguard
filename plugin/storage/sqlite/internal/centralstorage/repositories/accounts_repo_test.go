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

package repositories

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"

	_ "github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azidbtestutils "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerAccountForUpsertMocking registers an account for insert mocking.
func registerAccountForUpsertMocking(isCreate bool) (*Account, string, *sqlmock.Rows) {
	account := &Account{
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	var sql string
	if isCreate {
		sql =`INSERT INTO accounts \(account_id, name\) VALUES \(\?, \?\)`
	} else {
		sql = `UPDATE accounts SET name = \? WHERE account_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"}).
		AddRow(account.AccountID, account.CreatedAt, account.UpdatedAt, account.Name)
	return account, sql, sqlRows
}

// TestRepoCreateAccountWithInvalidInput tests the creation of an account with invalid input.
func TestRepoCreateAccountWithInvalidInput(t *testing.T) {
	assert := assert.New(t)

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{	// Test with nil account
		_, err := UpsertAccount(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{	// Test with invalid account id
		dbInAccount := &Account{
			AccountID: 0,
			Name: "rent-a-car",
		}
		_, err := UpsertAccount(tx, false, dbInAccount)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ 	// Test with invalid account name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			accountName := test
			_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInAccount := &Account{
				Name: accountName,
			}
			dbOutAccount, err := UpsertAccount(tx, true, dbInAccount)
			assert.NotNil(err, "error should be not nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutAccount, "accounts should be nil")
		}
	}
}

// TestRepoCreateAccountWithSuccess tests the creation of an account with success.
func TestRepoCreateAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)
	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		account, sql, sqlAccountRows := registerAccountForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInAccount *Account
		if isCreate {
			dbInAccount = &Account{
				Name: account.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), account.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInAccount = &Account{
				AccountID: account.AccountID,
				Name: account.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(account.Name, account.AccountID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT account_id, created_at, updated_at, name FROM accounts WHERE account_id = \?`).
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(sqlAccountRows)


		tx, _ := sqlDB.Begin()
		dbOutAccount, err := UpsertAccount(tx, isCreate, dbInAccount)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutAccount, "account should be not nil")
		assert.Equal(account.AccountID, dbOutAccount.AccountID, "account name is not correct")
		assert.Equal(account.Name, dbOutAccount.Name, "account name is not correct")
		assert.Nil(err, "error should be nil")
	}
}
