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

package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"

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
		storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
		defer sqlDB.Close()

		account := &azmodels.Account{
			Name: accountName,
		}
		account, err := storage.CreateAccount(account)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
		assert.Nil(account, "accounts should be nil")
	}
}

// TestAAPCreateAccountWithDuplicateError tests the creation of an account with a duplicate error.
func TestAAPCreateAccountWithDuplicateError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, _ := registerAccountForInsertMocking()

	mock.ExpectBegin()
	mock.ExpectQuery(accountsSQL).WillReturnError(&pgconn.PgError{ Code: "23505" })
	mock.ExpectRollback()

	inputAccount := &azmodels.Account{
		Name: account.Name,
	}
	outputAccount, err := storage.CreateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageDuplicate, err), "error should be ErrStorageDuplicate")
}

// TestAAPCreateAccountWithGenericError tests the creation of an account with a generic error.
func TestAAPCreateAccountWithGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, _ := registerAccountForInsertMocking()

	mock.ExpectBegin()
	mock.ExpectQuery(accountsSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputAccount := &azmodels.Account{
		Name: account.Name,
	}
	outputAccount, err := storage.CreateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestAAPCreateAccountWithTenantCreationError tests the creation of an account with a tenant creation error.
func TestAAPCreateAccountWithTenantCreationError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts := registerAccountForInsertMocking()
	_, tenantsSQL, _ := registerTenantsForInsertMocking(account, "default")

	mock.ExpectBegin()
	mock.ExpectQuery(accountsSQL).WillReturnRows(sqlAccounts)
	mock.ExpectQuery(tenantsSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputAccount := &azmodels.Account{
		Name: account.Name,
	}
	outputAccount, err := storage.CreateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestAAPCreateAccountWithIdentitySourceCreationError tests the creation of an account with an identity source creation error.
func TestAAPCreateAccountWithIdentitySourceCreationError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts := registerAccountForInsertMocking()
	_, tenantsSQL, sqlTenants := registerTenantsForInsertMocking(account, "default")
	_, identitySourcesSQL, _ := registerIdentitySourceForInsertMocking(account, "default")

	mock.ExpectBegin()
	mock.ExpectQuery(accountsSQL).WillReturnRows(sqlAccounts)
	mock.ExpectQuery(tenantsSQL).WillReturnRows(sqlTenants)
	mock.ExpectQuery(identitySourcesSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputAccount := &azmodels.Account{
		Name: account.Name,
	}
	outputAccount, err := storage.CreateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestAAPCreateAccountWithNil tests the creation of an account with a nil account.
func TestAAPCreateAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts := registerAccountForInsertMocking()
	_, tenantsSQL, sqlTenants := registerTenantsForInsertMocking(account, "default")
	_, identitySourcesSQL, sqlIdentitySources := registerIdentitySourceForInsertMocking(account, "default")

	mock.ExpectBegin()
	mock.ExpectQuery(accountsSQL).WillReturnRows(sqlAccounts)
	mock.ExpectQuery(tenantsSQL).WillReturnRows(sqlTenants)
	mock.ExpectQuery(identitySourcesSQL).WillReturnRows(sqlIdentitySources)
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

// TestAAPUpdateAccountWithInvalidAccountID tests the update of an account with an invalid account ID.
func TestAAPUpdateAccountWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account := &azmodels.Account{
		AccountID: -1,
		Name: "default",
	}
	account, err := storage.UpdateAccount(account)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPUpdateAccountWithInvalidName tests the update of an account with invalid name.
func TestAAPUpdateAccountWithInvalidName(t *testing.T) {
	assert := assert.New(t)

	tests := []string{
		"",
		" ",
		"@",
		"1aX",
		"X-@x"}
	for _, test := range tests {
		accountName := test
		storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
		defer sqlDB.Close()

		account := &azmodels.Account{
			AccountID: 581616507495,
			Name: accountName,
		}
		account, err := storage.UpdateAccount(account)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
		assert.Nil(account, "accounts should be nil")
	}
}

// TestAAPUpdateANotExistingAccount	tests the update of an account that does not exist.
func TestAAPUpdateANotExistingAccount(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()

	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputAccount := &azmodels.Account{
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputAccount, err := storage.UpdateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

// TestAAPUpdateAnAccountWithDuplicatedName tests the update of an account with a duplicated name.
func TestAAPUpdateAnAccountWithDuplicatedName(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts, _ := registerAccountForUpdateMocking()

	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlAccounts)
	mock.ExpectBegin()
	mock.ExpectExec(accountsSQL).WillReturnError(&pgconn.PgError{ Code: "23505" })
	mock.ExpectRollback()

	inputAccount := &azmodels.Account{
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputAccount, err := storage.UpdateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageDuplicate, err), "error should be ErrStorageDuplicate")
}

// TestAAPUpdateAnAccountWithGenericError tests the update of an account with a generic error.
func TestAAPUpdateAnAccountWithGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts, _ := registerAccountForUpdateMocking()

	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlAccounts)
	mock.ExpectBegin()
	mock.ExpectExec(accountsSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputAccount := &azmodels.Account{
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputAccount, err := storage.UpdateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

func TestAAPUpdateAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts, sqlAccountResult := registerAccountForUpdateMocking()

	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlAccounts)
	mock.ExpectBegin()
	mock.ExpectExec(accountsSQL).WillReturnResult(sqlAccountResult)
	mock.ExpectCommit()

	inputAccount := &azmodels.Account{
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputAccount, err := storage.UpdateAccount(inputAccount)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputAccount, "account should be not nil")
	assert.Equal(account.AccountID, outputAccount.AccountID, "account name is not correct")
	assert.Equal(account.Name, outputAccount.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestAAPDeleteAccountWithInvalidAccountID tests the deletion of an account with an invalid account ID.
func TestAAPDeleteAccountWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account := &azmodels.Account{
		AccountID: -1,
		Name: "default",
	}
	account, err := storage.DeleteAccount(account.AccountID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}


// TestAAPDeleteANotExistingAccount tests the deletion of an account that does not exist.
func TestAAPDeleteANotExistingAccount(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForDeleteMocking()

	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputAccount := &azmodels.Account{
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputAccount, err := storage.DeleteAccount(inputAccount.AccountID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

// TestAAPDeleteWithGenericError tests the deletion of an account with a generic error.
func TestAAPDeleteWithGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts, _ := registerAccountForDeleteMocking()

	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlAccounts)
	mock.ExpectBegin()
	mock.ExpectExec(accountsSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputAccount := &azmodels.Account{
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputAccount, err := storage.DeleteAccount(inputAccount.AccountID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestAAPDeleteAccountWithSuccess tests the deletion of an account with success.
func TestAAPDeleteAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, accountsSQL, sqlAccounts, sqlAccountResult := registerAccountForDeleteMocking()

	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlAccounts)
	mock.ExpectBegin()
	mock.ExpectExec(accountsSQL).WillReturnResult(sqlAccountResult)
	mock.ExpectCommit()

	inputAccount := &azmodels.Account{
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputAccount, err := storage.DeleteAccount(inputAccount.AccountID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputAccount, "account should be not nil")
	assert.Equal(account.AccountID, outputAccount.AccountID, "account name is not correct")
	assert.Equal(account.Name, outputAccount.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestAAPGetAllAccountsWithInvalidAccountID tests the retrieval of an account with an invalid account ID.
func TestAAPGetAllAccountsWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tests := []any{
		"",
		"a4ds",
		"1sdfa5",
		"-1",
		"0",
		-1,
		0,
		int64(-1),
		int64(0),
	}
	for _, test := range tests {
		account, err := storage.GetAllAccounts(map[string]any{ azmodels.FieldAccountAccountID: test })
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
		assert.Nil(account, "accounts should be nil")
	}
}


// TestAAPGetAllAccountsWithInvalidAccountName tests the retrieval of an account with an invalid account name.
func TestAAPGetAllAccountsWithInvalidAccountName(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tests := []any{
		0,
		"",
		" ",
		"1 ",
		"-1",
		"0",
	}
	for _, test := range tests {
		account, err := storage.GetAllAccounts(map[string]any{ azmodels.FieldAccountName: test })
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
		assert.Nil(account, "accounts should be nil")
	}
}

// TestAAPGetAllAccountsWithNotExistingAccount  tests the retrieval of an account that does not exist.
func TestAAPGetAllAccountsWithNotExistingAccount(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	accounts, _, _ := registerAccountForGetAllMocking()


	accountsSQLSelect := "SELECT .+ FROM \"accounts\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	outputAccount, err := storage.GetAllAccounts(map[string]any{ azmodels.FieldAccountAccountID: accounts[0].AccountID, azmodels.FieldAccountName: accounts[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputAccount, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

// TestAAPGetAllAccountsWithSuccess tests the retrieval of an account with success.
func TestAAPGetAllAccountsWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	accounts, accountsSQL, sqlAccounts := registerAccountForGetAllMocking()

	mock.ExpectQuery(accountsSQL).WillReturnRows(sqlAccounts)

	outputAccounts, err := storage.GetAllAccounts(map[string]any{ azmodels.FieldAccountAccountID: accounts[0].AccountID, azmodels.FieldAccountName: accounts[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputAccounts, "account should be not nil")
	assert.Equal(len(accounts), len(outputAccounts), "accounts should be equal")
	for i, account := range accounts {
		assert.Equal(account.AccountID, outputAccounts[i].AccountID, "account id is not correct")
		assert.Equal(account.Name, outputAccounts[i].Name, "account name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
