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

func TestAAPCreateIdentityWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	identityName := "company-a"
	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identity := &azmodels.Identity{
		Name: identityName,
	}
	account, err := storage.CreateIdentity(identity)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPCreateIdentityWithInvalidName tests the creation of an identity with an invalid name.
func TestAAPCreateIdentityWithInvalidName(t *testing.T) {
	assert := assert.New(t)

	tests := []string{
		"",
		" ",
		"@",
		"1aX",
		"X-@x"}
	for _, test := range tests {
		identityName := test
		storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
		defer sqlDB.Close()

		identity := &azmodels.Identity{
			AccountID: 581616507495,
			Name: identityName,
		}
		outputIdentity, err := storage.CreateIdentity(identity)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
		assert.Nil(outputIdentity, "accounts should be nil")
	}
}

// TestAAPCreateIdentityWithDuplicateError tests the creation of an identity with a duplicate error.
func TestAAPCreateIdentityWithDuplicateError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	_, _, sqlIdentitySources := registerIdentitySourceForInsertMocking(account, "")
	identity, identitiesSQL, _ := registerIdentityForInsertMocking(account, "")

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)
	mock.ExpectBegin()
	mock.ExpectQuery(identitiesSQL).WillReturnError(&pgconn.PgError{ Code: "23505" })
	mock.ExpectRollback()

	inputIdentity := &azmodels.Identity{
		IdentitySourceID: identity.IdentitySourceID,
		AccountID: identity.AccountID,
		Kind: identity.Kind,
		Name: identity.Name,
	}
	outputIdentity, err := storage.CreateIdentity(inputIdentity)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentity, "identity should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageDuplicate, err), "error should be ErrStorageDuplicate")
}

// TestAAPCreateIdentityWithGenericError tests the creation of an identity with a generic error.
func TestAAPCreateIdentityWithGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	_, _, sqlIdentitySources := registerIdentitySourceForInsertMocking(account, "")
	identity, identitiesSQL, _ := registerIdentityForInsertMocking(account, "")

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)
	mock.ExpectBegin()
	mock.ExpectQuery(identitiesSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputIdentity := &azmodels.Identity{
		IdentitySourceID: identity.IdentitySourceID,
		AccountID: identity.AccountID,
		Kind: identity.Kind,
		Name: identity.Name,
	}
	outputIdentity, err := storage.CreateIdentity(inputIdentity)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentity, "identity should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestAAPIdentityAccountWithSuccess tests the creation of an identity with success.
func TestAAPCreateIdentityAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	_, _, sqlIdentitySources := registerIdentitySourceForInsertMocking(account, "")
	identity, identitiesSQL, sqlIdentities := registerIdentityForInsertMocking(account, "default")

	identitySourcesSQLSelect := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	mock.ExpectQuery(identitySourcesSQLSelect).WillReturnRows(sqlIdentitySources)
	mock.ExpectBegin()
	mock.ExpectQuery(identitiesSQL).WillReturnRows(sqlIdentities)
	mock.ExpectCommit()

	inputIdentity := &azmodels.Identity{
		IdentitySourceID: identity.IdentitySourceID,
		AccountID: identity.AccountID,
		Kind: identity.Kind,
		Name: identity.Name,
	}
	outputIdentity, err := storage.CreateIdentity(inputIdentity)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentity, "identity should be not nil")
	assert.Equal(identity.AccountID, outputIdentity.AccountID, "identity name is not correct")
	assert.Equal(identity.Name, outputIdentity.Name, "identity name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestAAPUpdateIdentityWithInvalidIdentityID tests the update of an identity with an invalid identity ID.
func TestAAPUpdateIdentityWithInvalidIdentityID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	identity, _, _ := registerIdentityForInsertMocking(account, "default")

	inputIdentity := &azmodels.Identity{
		IdentitySourceID: identity.IdentitySourceID,
		AccountID: identity.AccountID,
		Kind: identity.Kind,
		Name: identity.Name,
	}
	outputIdentity, err := storage.UpdateIdentity(inputIdentity)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
	assert.Nil(outputIdentity, "accounts should be nil")
}

// TestAAPUpdateIdentityWithSuccess tests the update of an identity with success.
func TestAAPUpdateIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identity, identitiesSQL, sqlIdentities, sqlIdentityResult := registerIdentityForUpdateMocking(account, "businessx")

	identitiesSQLSelect := "SELECT .+ FROM \"identities\" WHERE .+"
	mock.ExpectQuery(identitiesSQLSelect).WillReturnRows(sqlIdentities)
	mock.ExpectBegin()
	mock.ExpectExec(identitiesSQL).WillReturnResult(sqlIdentityResult)
	mock.ExpectCommit()

	inputIdentity := &azmodels.Identity{
		IdentityID: identity.IdentityID,
		IdentitySourceID: identity.IdentitySourceID,
		AccountID: account.AccountID,
		Kind: identity.Kind,
		Name: account.Name,
	}
	outputIdentity, err := storage.UpdateIdentity(inputIdentity)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentity, "identity should be not nil")
	assert.Equal(outputIdentity.AccountID, outputIdentity.AccountID, "identity name is not correct")
	assert.Equal(outputIdentity.Name, outputIdentity.Name, "identity name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestAAPDeleteIdentityWithInvalidAccountID tests the deletion of an identity with an invalid account ID.
func TestAAPDeleteIdentityWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identity := &azmodels.Identity{
		IdentityID: "f2061bdb-3fcb-4561-bef6-04c535c2f5be",
		AccountID: -1,
		Name: "default",
	}
	account, err := storage.DeleteIdentity(identity.AccountID, identity.IdentityID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPDeleteIdentityWithInvalidIdentityID tests the deletion of an identity with an invalid identity ID.
func TestAAPDeleteIdentityWithInvalidIdentityID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identity := &azmodels.Identity{
		IdentityID: "not valid",
		AccountID: 581616507495,
		Name: "default",
	}
	account, err := storage.DeleteIdentity(identity.AccountID, identity.IdentityID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be ErrClientID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPDeleteANotExistingIdentity tests the deletion of an identity that does not exist.
func TestAAPDeleteANotExistingIdentity(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identity, _, _, _ := registerIdentityForUpdateMocking(account, "businessx")

	identitiesSQLSelect := "SELECT .+ FROM \"identities\" WHERE .+"
	mock.ExpectQuery(identitiesSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputIdentity := &azmodels.Identity{
		IdentityID: identity.IdentityID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputIdentity, err := storage.DeleteIdentity(inputIdentity.AccountID, inputIdentity.IdentityID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentity, "identity should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

func TestAAPDeleteAnIdentityWithAGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identity, identitiesSQL, sqlIdentities, _ := registerIdentityForDeleteMocking(account, "businessx")

	identitiesSQLSelect := "SELECT .+ FROM \"identities\" WHERE .+"
	mock.ExpectQuery(identitiesSQLSelect).WillReturnRows(sqlIdentities)
	mock.ExpectBegin()
	mock.ExpectExec(identitiesSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputIdentity := &azmodels.Identity{
		IdentityID: identity.IdentityID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputIdentity, err := storage.DeleteIdentity(inputIdentity.AccountID, inputIdentity.IdentityID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentity, "identity should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageNotFound")
}

// TestAAPDeleteIdentitiesWithSuccess tests the deletion of an identity with success.
func TestAAPDeleteIdentitiesWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	identity, identitiesSQL, sqlIdentities, sqlIdentityResult := registerIdentityForDeleteMocking(account, "businessx")

	identitiesSQLSelect := "SELECT .+ FROM \"identities\" WHERE .+"
	mock.ExpectQuery(identitiesSQLSelect).WillReturnRows(sqlIdentities)
	mock.ExpectBegin()
	mock.ExpectExec(identitiesSQL).WillReturnResult(sqlIdentityResult)
	mock.ExpectCommit()

	inputIdentity := &azmodels.Identity{
		IdentityID: identity.IdentityID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputIdentity, err := storage.DeleteIdentity(inputIdentity.AccountID, inputIdentity.IdentityID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentity, "account should be not nil")
	assert.Equal(outputIdentity.IdentityID, outputIdentity.IdentityID, "account name is not correct")
	assert.Equal(outputIdentity.AccountID, outputIdentity.AccountID, "account name is not correct")
	assert.Equal(outputIdentity.Name, outputIdentity.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestAAPGetAllIdentitiesWithInvalidAccountID tests the retrieval of all identities with an invalid account ID.
func TestAAPGetAllIdentitiesWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tests := []int64{
		int64(-1),
		int64(0),
	}
	for _, test := range tests {
		account, err := storage.GetAllIdentities(test,nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
		assert.Nil(account, "accounts should be nil")
	}
}

// TestAAPGetAllIdentitiesWithInvalidIdentitySourceID tests the retrieval of all identities with an invalid identity ID.
func TestAAPGetAllIdentitiesWithInvalidIdentityID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identities, err := storage.GetAllIdentities(581616507495, map[string]any { azmodels.FieldIdentityIdentityID: 1 })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientUUID")
	assert.Nil(identities, "identities should be nil")

	identities, err = storage.GetAllIdentities(581616507495, map[string]any { azmodels.FieldIdentityIdentityID: "sdfasfd" })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientUUID")
	assert.Nil(identities, "identities should be nil")

	identities, err = storage.GetAllIdentities(581616507495, map[string]any { azmodels.FieldIdentityIdentityID: "2943baee-9e37-4816-ac40-d58e3fd27587",
		azmodels.FieldIdentityIdentitySourceID: " sdfafdsa" })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientUUID")
	assert.Nil(identities, "identities should be nil")

	identities, err = storage.GetAllIdentities(581616507495, map[string]any { azmodels.FieldIdentityIdentityID: "2943baee-9e37-4816-ac40-d58e3fd27587",
		azmodels.FieldIdentityIdentitySourceID: " dsaf as" })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientUUID")
	assert.Nil(identities, "identities should be nil")

	identities, err = storage.GetAllIdentities(581616507495, map[string]any { azmodels.FieldIdentityIdentityID: "2943baee-9e37-4816-ac40-d58e3fd27587",
		azmodels.FieldIdentityIdentitySourceID: "595d3ff7-0d1d-4728-b40f-5d05c0f144cd", azmodels.FieldIdentityKind: "sfsadfa" })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientGeneric, err), "error should be ErrClientUUID")
	assert.Nil(identities, "identities should be nil")
}

// TestAAPGetAllIdentitiesWithInvalidIdentitySourceName tests the retrieval of all identities with an invalid identity name.
func TestAAPGetAllIdentitiesWithInvalidIdentitySourceName(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identities, err := storage.GetAllIdentities(581616507495, map[string]any {
		azmodels.FieldIdentityIdentityID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldIdentityName: 1,
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(identities, "accounts should be nil")

	identities, err = storage.GetAllIdentities(581616507495, map[string]any {
		azmodels.FieldIdentityIdentityID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldIdentityName: "a d d",
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(identities, "accounts should be nil")
}

func TestAAPGetAllIdentitiesWithNotExistingIdentity(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identities, _, _ := registerIdentityForGetAllMocking()


	identitiesSQLSelect := "SELECT .+ FROM \"identities\" WHERE .+"
	mock.ExpectQuery(identitiesSQLSelect).WillReturnError(errors.New("something bad has happened"))

	outputIdentity, err := storage.GetAllIdentities(581616507495, map[string]any{
		azmodels.FieldIdentityIdentityID: identities[0].IdentityID,
		azmodels.FieldIdentityName: identities[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputIdentity, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

func TestAAPGetAllIdentitiesWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	identities, _, sqlIdentities := registerIdentityForGetAllMocking()


	identitiesSQLSelect := "SELECT .+ FROM \"identities\" WHERE .+"
	mock.ExpectQuery(identitiesSQLSelect).WillReturnRows(sqlIdentities)

	outputIdentity, err := storage.GetAllIdentities(581616507495, map[string]any{
		azmodels.FieldIdentityIdentityID: identities[0].IdentityID,
		azmodels.FieldIdentityName: identities[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputIdentity, "account should be not nil")
	assert.Equal(len(identities), len(outputIdentity), "accounts should be equal")
	for i, account := range outputIdentity {
		assert.Equal(account.IdentityID, outputIdentity[i].IdentityID, "identity id is not correct")
		assert.Equal(account.AccountID, outputIdentity[i].AccountID, "identity account id is not correct")
		assert.Equal(account.Name, outputIdentity[i].Name, "identity srouce name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
