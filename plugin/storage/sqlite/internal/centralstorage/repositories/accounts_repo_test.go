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
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"

	"github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azidbtestutils "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerAccountForUpsertMocking registers an account for upsert mocking.
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

// registerAccountForDeleteMocking registers an account for delete mocking.
func registerAccountForDeleteMocking() (string, *Account, *sqlmock.Rows, string) {
	account := &Account{
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	var sqlSelect = `SELECT account_id, created_at, updated_at, name FROM accounts WHERE account_id = \?`
	var sqlDelete = `DELETE FROM accounts WHERE account_id = \?`
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"}).
		AddRow(account.AccountID, account.CreatedAt, account.UpdatedAt, account.Name)
	return sqlSelect, account, sqlRows, sqlDelete
}

// registerAccountForFetchMocking registers an account for fetch mocking.
func registerAccountForFetchMocking() (string, []Account, *sqlmock.Rows) {
	accounts := []Account {
		{
			AccountID: 581616507495,
			Name: "rent-a-car",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	var sqlSelect = "SELECT * FROM accounts WHERE account_id = ? AND name LIKE ? ORDER BY account_id LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"}).
		AddRow(accounts[0].AccountID, accounts[0].CreatedAt, accounts[0].UpdatedAt, accounts[0].Name)
	return sqlSelect, accounts, sqlRows
}

// TestRepoUpsertAccountWithInvalidInput tests the upsert of an account with invalid input.
func TestRepoUpsertAccountWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{	// Test with nil account
		_, err := repo.UpsertAccount(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{	// Test with invalid account id
		dbInAccount := &Account{
			AccountID: 0,
			Name: "rent-a-car",
		}
		_, err := repo.UpsertAccount(tx, false, dbInAccount)
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
			dbOutAccount, err := repo.UpsertAccount(tx, true, dbInAccount)
			assert.NotNil(err, "error should be not nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutAccount, "accounts should be nil")
		}
	}
}

// TestRepoUpsertAccountWithSuccess tests the upsert of an account with success.
func TestRepoUpsertAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

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
		dbOutAccount, err := repo.UpsertAccount(tx, isCreate, dbInAccount)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutAccount, "account should be not nil")
		assert.Equal(account.AccountID, dbOutAccount.AccountID, "account name is not correct")
		assert.Equal(account.Name, dbOutAccount.Name, "account name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoCreateAccountWithSuccess tests the upsert of an account with success.
func TestRepoUpsertAccountWithErrors(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		account, sql, _ := registerAccountForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInAccount *Account
		if isCreate {
			dbInAccount = &Account{
				Name: account.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), account.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique })
		} else {
			dbInAccount = &Account{
				AccountID: account.AccountID,
				Name: account.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(account.Name, account.AccountID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique })
		}

		tx, _ := sqlDB.Begin()
		dbOutAccount, err := repo.UpsertAccount(tx, isCreate, dbInAccount)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutAccount, "account should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteAccountWithInvalidInput tests the delete of an account with invalid input.
func TestRepoDeleteAccountWithInvalidInput(t *testing.T) {
	repo := Repo{}

	assert := assert.New(t)
	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{	// Test with invalid account id
		_, err := repo.DeleteAccount(tx, 0)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}


// TestRepoDeleteAccountWithSuccess tests the delete of an account with success.
func TestRepoDeleteAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, account, sqlAccountRows, sqlDelete := registerAccountForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlAccountRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutAccount, err := repo.DeleteAccount(tx, account.AccountID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutAccount, "account should be not nil")
	assert.Equal(account.AccountID, dbOutAccount.AccountID, "account name is not correct")
	assert.Equal(account.Name, dbOutAccount.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestRepoDeleteAccountWithErrors tests the delete of an account with errors.
func TestRepoDeleteAccountWithErrors(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	tests := []int{
		1,
		2,
		3,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		sqlSelect, account, sqlAccountRows, sqlDelete := registerAccountForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound })
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnRows(sqlAccountRows)
		}

		if test == 2 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrPerm })
		} else if test == 3 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		tx, _ := sqlDB.Begin()
		dbOutAccount, err := repo.DeleteAccount(tx, account.AccountID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutAccount, "account should be nil")
		assert.NotNil(err, "error should be not nil")

		if test == 1 {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be errstoragenotfound")
		} else {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be errstoragegeneric")
		}
	}
}

// TestRepoFetchAccountWithInvalidInput tests the fetch of accounts with invalid input.
func TestRepoFetchAccountWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{	// Test with invalid page
		_, err := repo.FetchAccounts(sqlDB, 0, 100, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid page size
		_, err := repo.FetchAccounts(sqlDB, 1, 0, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid account id
		accountID := int64(0)
		_, err := repo.FetchAccounts(sqlDB, 1, 1, &accountID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{	// Test with invalid account id
		accountName := "@"
		_, err := repo.FetchAccounts(sqlDB, 1, 1, nil, &accountName)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be errclientname")
	}
}

// TestRepoFetchAccountWithSuccess tests the fetch of accounts with success.
func TestRepoFetchAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlAccounts, sqlAccountRows := registerAccountForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	accountName := "%" + sqlAccounts[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlAccounts[0].AccountID, accountName, pageSize, page - 1).
		WillReturnRows(sqlAccountRows)

	dbOutAccount, err := repo.FetchAccounts(sqlDB, page, pageSize, &sqlAccounts[0].AccountID, &sqlAccounts[0].Name)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutAccount, "account should be not nil")
	assert.Len(dbOutAccount, len(sqlAccounts), "accounts len should be correct")
	for i, account := range dbOutAccount {
		assert.Equal(account.AccountID, sqlAccounts[i].AccountID, "account name is not correct")
		assert.Equal(account.Name, sqlAccounts[i].Name, "account name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
