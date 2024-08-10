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

func TestAAPCreateIdentitySourceWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	identitySourceName := "company-a"
	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identitySource := &azmodels.IdentitySource{
		Name: identitySourceName,
	}
	account, err := storage.CreateIdentitySource(identitySource)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPCreateIdentitySourceWithInvalidName tests the creation of an identity source with an invalid name.
func TestAAPCreateIdentitySourceWithInvalidName(t *testing.T) {
	assert := assert.New(t)

	tests := []string{
		"",
		" ",
		"@",
		"1aX",
		"X-@x"}
	for _, test := range tests {
		identitySourceName := test
		storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
		defer sqlDB.Close()

		identitySource := &azmodels.IdentitySource{
			AccountID: 581616507495,
			Name: identitySourceName,
		}
		outputIdentitySource, err := storage.CreateIdentitySource(identitySource)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
		assert.Nil(outputIdentitySource, "accounts should be nil")
	}
}

// TestAAPCreateIdentitySourceWithDuplicateError tests the creation of an identity source with a duplicate error.
func TestAAPCreateIdentitySourceWithDuplicateError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	identitySource, identitySourcesSQL, _ := registerIdentitySourceForInsertMocking(account, "")

	mock.ExpectBegin()
	mock.ExpectQuery(identitySourcesSQL).WillReturnError(&pgconn.PgError{ Code: "23505" })
	mock.ExpectRollback()

	inputIdentitySource := &azmodels.IdentitySource{
		AccountID: 581616507495,
		Name: identitySource.Name,
	}
	outputIdentitySource, err := storage.CreateIdentitySource(inputIdentitySource)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentitySource, "identity source should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageDuplicate, err), "error should be ErrStorageDuplicate")
}

// TestAAPCreateIdentitySourceWithGenericError tests the creation of an identity source with a generic error.
func TestAAPCreateIdentitySourceWithGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	identitySource, identitySourcesSQL, _ := registerIdentitySourceForInsertMocking(account, "")

	mock.ExpectBegin()
	mock.ExpectQuery(identitySourcesSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputIdentitySource := &azmodels.IdentitySource{
		AccountID: 581616507495,
		Name: identitySource.Name,
	}
	outputIdentitySource, err := storage.CreateIdentitySource(inputIdentitySource)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentitySource, "identity source should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestAAPIdentitySourceAccountWithSuccess tests the creation of an identity source with success.
func TestAAPCreateIdentitySourceAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	identitySource, identitySourcesSQL, sqlIdentitySources := registerIdentitySourceForInsertMocking(account, "default")

	mock.ExpectBegin()
	mock.ExpectQuery(identitySourcesSQL).WillReturnRows(sqlIdentitySources)
	mock.ExpectCommit()

	inputIdentitySource := &azmodels.IdentitySource{
		AccountID: 581616507495,
		Name: identitySource.Name,
	}
	outputIdentitySource, err := storage.CreateIdentitySource(inputIdentitySource)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentitySource, "identity source should be not nil")
	assert.Equal(identitySource.AccountID, outputIdentitySource.AccountID, "identity source name is not correct")
	assert.Equal(identitySource.Name, outputIdentitySource.Name, "identity source name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestAAPUpdateIdentitySourceWithInvalidIdentitySourceID tests the update of an identity source with an invalid identity source ID.
func TestAAPUpdateIdentitySourceWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identitySource := &azmodels.IdentitySource{
		IdentitySourceID: "invalid",
		AccountID: 581616507495,
		Name: "authx",
	}
	identitySource, err := storage.UpdateIdentitySource(identitySource)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
	assert.Nil(identitySource, "accounts should be nil")
}

// TestAAPUpdateIdentitySourceWithInvalidDefaultName tests the update of an identity source with an invalid default name.
func TestAAPUpdateIdentitySourceWithInvalidDefaultName(t *testing.T) {
	assert := assert.New(t)

	account, _, _ := registerAccountForInsertMocking()
	identitySource, _, _, _ := registerIdentitySourceForUpdateMocking(account, "authx")

	identitySourceName := IdentitySourceDefaultName
	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	inputIdentitySource := &azmodels.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		AccountID: 581616507495,
		Name: identitySourceName,
	}
	outputIdentitySource, err := storage.UpdateIdentitySource(inputIdentitySource)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
	assert.Nil(outputIdentitySource, "accounts should be nil")
}

// TestAAPUpdateIdentitySourceWithSuccess tests the update of an identity source with success.
func TestAAPUpdateIdentitySourceWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identitySource, identitySourcesSQL, sqlIdentitySources, sqlIdentitySourceResult := registerIdentitySourceForUpdateMocking(account, "authx")

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)
	mock.ExpectBegin()
	mock.ExpectExec(identitySourcesSQL).WillReturnResult(sqlIdentitySourceResult)
	mock.ExpectCommit()

	inputIdentitySource := &azmodels.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputIdentitySource, err := storage.UpdateIdentitySource(inputIdentitySource)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentitySource, "identity source should be not nil")
	assert.Equal(outputIdentitySource.AccountID, outputIdentitySource.AccountID, "identity source name is not correct")
	assert.Equal(outputIdentitySource.Name, outputIdentitySource.Name, "identity source name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestAAPDeleteIdentitySourceWithInvalidAccountID tests the deletion of an identity source with an invalid account ID.
func TestAAPDeleteIdentitySourceWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identitySource := &azmodels.IdentitySource{
		IdentitySourceID: "f2061bdb-3fcb-4561-bef6-04c535c2f5be",
		AccountID: -1,
	}
	account, err := storage.DeleteIdentitySource(identitySource.AccountID, identitySource.IdentitySourceID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPDeleteIdentitySourceWithInvalidIdentitySourceID tests the deletion of an identity source with an invalid identity source ID.
func TestAAPDeleteIdentitySourceWithInvalidIdentitySourceID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identitySource := &azmodels.IdentitySource{
		IdentitySourceID: "not valid",
		AccountID: 581616507495,
	}
	account, err := storage.DeleteIdentitySource(identitySource.AccountID, identitySource.IdentitySourceID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be ErrClientID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPDeleteANotExistingIdentitySource tests the deletion of an identity source that does not exist.
func TestAAPDeleteANotExistingIdentitySource(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identitySource, _, _, _ := registerIdentitySourceForUpdateMocking(account, "authx")

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputIdentitySource := &azmodels.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		AccountID: account.AccountID,
	}
	outputIdentitySource, err := storage.DeleteIdentitySource(inputIdentitySource.AccountID, inputIdentitySource.IdentitySourceID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentitySource, "identity source should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

// TestAAPDeleteADefaultIdentitySource tests the deletion of a default identity source.
func TestAAPDeleteADefaultIdentitySource(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identitySource, _, sqlIdentitySources, _ := registerIdentitySourceForUpdateMocking(account, IdentitySourceDefaultName)

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)

	inputIdentitySource := &azmodels.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		AccountID: account.AccountID,
	}
	outputIdentitySource, err := storage.DeleteIdentitySource(inputIdentitySource.AccountID, inputIdentitySource.IdentitySourceID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentitySource, "identity source should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageNotFound")
}

func TestAAPDeleteAnIdentitySourceWithAGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identitySource, identitySourcesSQL, sqlIdentitySources, _ := registerIdentitySourceForDeleteMocking(account, "authx")

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)
	mock.ExpectBegin()
	mock.ExpectExec(identitySourcesSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputIdentitySource := &azmodels.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		AccountID: account.AccountID,
	}
	outputIdentitySource, err := storage.DeleteIdentitySource(inputIdentitySource.AccountID, inputIdentitySource.IdentitySourceID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentitySource, "identity source should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageNotFound")
}

// TestAAPDeleteIdentitySourcesWithSuccess tests the deletion of an identity source with success.
func TestAAPDeleteIdentitySourcesWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identitySource, identitySourcesSQL, sqlIdentitySources, sqlIdentitySourceResult := registerIdentitySourceForDeleteMocking(account, "authx")

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)
	mock.ExpectBegin()
	mock.ExpectExec(identitySourcesSQL).WillReturnResult(sqlIdentitySourceResult)
	mock.ExpectCommit()

	inputIdentitySource := &azmodels.IdentitySource{
		IdentitySourceID: identitySource.IdentitySourceID,
		AccountID: account.AccountID,
	}
	outputIdentitySource, err := storage.DeleteIdentitySource(inputIdentitySource.AccountID, inputIdentitySource.IdentitySourceID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentitySource, "account should be not nil")
	assert.Equal(outputIdentitySource.IdentitySourceID, outputIdentitySource.IdentitySourceID, "account name is not correct")
	assert.Equal(outputIdentitySource.AccountID, outputIdentitySource.AccountID, "account name is not correct")
	assert.Equal(outputIdentitySource.Name, outputIdentitySource.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestAAPGetAllIdentitySourcesWithInvalidAccountID tests the retrieval of all identity sources with an invalid account ID.
func TestAAPGetAllIdentitySourcesWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tests := []int64{
		int64(-1),
		int64(0),
	}
	for _, test := range tests {
		account, err := storage.GetAllIdentitySources(test,nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
		assert.Nil(account, "accounts should be nil")
	}
}

// TestAAPGetAllIdentitySourcesWithInvalidIdentitySourceID tests the retrieval of all identity sources with an invalid identity source ID.
func TestAAPGetAllIdentitySourcesWithInvalidIdentitySourceID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, err := storage.GetAllIdentitySources(581616507495, map[string]any { azmodels.FieldIdentitySourceIdentitySourceID: 1 })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")

	account, err = storage.GetAllIdentitySources(581616507495, map[string]any { azmodels.FieldIdentitySourceIdentitySourceID: "sdfasfd" })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPGetAllIdentitySourcesWithInvalidIdentitySourceName tests the retrieval of all identity sources with an invalid identity source name.
func TestAAPGetAllIdentitySourcesWithInvalidIdentitySourceName(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, err := storage.GetAllIdentitySources(581616507495, map[string]any {
		azmodels.FieldIdentitySourceIdentitySourceID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldIdentitySourceName: 1,
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")

	account, err = storage.GetAllIdentitySources(581616507495, map[string]any {
		azmodels.FieldIdentitySourceIdentitySourceID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldIdentitySourceName: "a d d",
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

func TestAAPGetAllIdentitySourcesWithNotExistingIdentitySource(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identitySources, _, _ := registerIdentitySourceForGetAllMocking()


	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnError(errors.New("something bad has happened"))

	outputIdentitySource, err := storage.GetAllIdentitySources(581616507495, map[string]any{
		azmodels.FieldIdentitySourceIdentitySourceID: identitySources[0].IdentitySourceID,
		azmodels.FieldIdentitySourceName: identitySources[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentitySource, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

func TestAAPGetAllIdentitySourcesWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identitySources, _, sqlIdentitySources := registerIdentitySourceForGetAllMocking()


	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)

	outputIdentitySource, err := storage.GetAllIdentitySources(581616507495, map[string]any{
		azmodels.FieldIdentitySourceIdentitySourceID: identitySources[0].IdentitySourceID,
		azmodels.FieldIdentitySourceName: identitySources[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentitySource, "account should be not nil")
	assert.Equal(len(identitySources), len(outputIdentitySource), "accounts should be equal")
	for i, account := range outputIdentitySource {
		assert.Equal(account.IdentitySourceID, outputIdentitySource[i].IdentitySourceID, "identity source id is not correct")
		assert.Equal(account.AccountID, outputIdentitySource[i].AccountID, "identity source account id is not correct")
		assert.Equal(account.Name, outputIdentitySource[i].Name, "identity srouce name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
