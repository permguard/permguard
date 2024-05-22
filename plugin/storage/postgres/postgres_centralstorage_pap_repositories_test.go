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

func TestPAPCreateRepositoryWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	repositoryName := "company-a"
	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	repository := &azmodels.Repository{
		Name: repositoryName,
	}
	account, err := storage.CreateRepository(repository)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestPAPCreateRepositoryWithInvalidName tests the creation of an repository with an invalid name.
func TestPAPCreateRepositoryWithInvalidName(t *testing.T) {
	assert := assert.New(t)

	tests := []string{
		"",
		" ",
		"@",
		"1aX",
		"X-@x"}
	for _, test := range tests {
		repositoryName := test
		storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
		defer sqlDB.Close()

		repository := &azmodels.Repository{
			AccountID: 581616507495,
			Name: repositoryName,
		}
		outputRepository, err := storage.CreateRepository(repository)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
		assert.Nil(outputRepository, "accounts should be nil")
	}
}

// TestPAPCreateRepositoryWithDuplicateError tests the creation of an repository with a duplicate error.
func TestPAPCreateRepositoryWithDuplicateError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	repository, accountsSQL, _ := registerRepositoryForInsertMocking(account, "")

	mock.ExpectBegin()
	mock.ExpectBegin()
	mock.ExpectQuery(accountsSQL).WillReturnError(&pgconn.PgError{ Code: "23505" })
	mock.ExpectRollback()

	inputRepository := &azmodels.Repository{
		AccountID: 581616507495,
		Name: repository.Name,
	}
	outputRepository, err := storage.CreateRepository(inputRepository)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputRepository, "repository should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageDuplicate, err), "error should be ErrStorageDuplicate")
}

// TestPAPCreateRepositoryWithGenericError tests the creation of an repository with a generic error.
func TestPAPCreateRepositoryWithGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	repository, accountsSQL, _ := registerRepositoryForInsertMocking(account, "")

	mock.ExpectBegin()
	mock.ExpectBegin()
	mock.ExpectQuery(accountsSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputRepository := &azmodels.Repository{
		AccountID: 581616507495,
		Name: repository.Name,
	}
	outputRepository, err := storage.CreateRepository(inputRepository)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputRepository, "repository should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestPAPRepositoryAccountWithSuccess tests the creation of an repository with success.
func TestPAPCreateRepositoryAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	repository, repositoriesSQL, sqlRepositories := registerRepositoryForInsertMocking(account, "default")
	_, schemaSQL, sqlSchemas := registerSchemaForInsertMocking(account)

	mock.ExpectBegin()
	mock.ExpectBegin()
	mock.ExpectQuery(repositoriesSQL).WillReturnRows(sqlRepositories)
	mock.ExpectCommit()
	mock.ExpectQuery(schemaSQL).WillReturnRows(sqlSchemas)
	mock.ExpectCommit()

	inputRepository := &azmodels.Repository{
		AccountID: 581616507495,
		Name: repository.Name,
	}
	outputRepository, err := storage.CreateRepository(inputRepository)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputRepository, "repository should be not nil")
	assert.Equal(repository.AccountID, outputRepository.AccountID, "repository name is not correct")
	assert.Equal(repository.Name, outputRepository.Name, "repository name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestPAPUpdateRepositoryWithInvalidRepositoryID tests the update of an repository with an invalid repository ID.
func TestPAPUpdateRepositoryWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	repository := &azmodels.Repository{
		RepositoryID: "invalid",
		AccountID: 581616507495,
		Name: "businessx",
	}
	repository, err := storage.UpdateRepository(repository)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
	assert.Nil(repository, "accounts should be nil")
}

// TestPAPUpdateRepositoryWithInvalidDefaultName tests the update of an repository with an invalid default name.
func TestPAPUpdateRepositoryWithInvalidDefaultName(t *testing.T) {
	assert := assert.New(t)

	account, _, _ := registerAccountForInsertMocking()
	repository, _, _, _ := registerRepositoryForUpdateMocking(account, "businessx")

	repositoryName := RepositoryDefaultName
	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	inputRepository := &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		AccountID: 581616507495,
		Name: repositoryName,
	}
	outputRepository, err := storage.UpdateRepository(inputRepository)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
	assert.Nil(outputRepository, "accounts should be nil")
}

// TestPAPUpdateRepositoryWithSuccess tests the update of an repository with success.
func TestPAPUpdateRepositoryWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	repository, repositoriesSQL, sqlRepositories, sqlRepositoryResult := registerRepositoryForUpdateMocking(account, "businessx")

	accountsSQLSelect := "SELECT .+ FROM \"repositories\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlRepositories)
	mock.ExpectBegin()
	mock.ExpectExec(repositoriesSQL).WillReturnResult(sqlRepositoryResult)
	mock.ExpectCommit()

	inputRepository := &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputRepository, err := storage.UpdateRepository(inputRepository)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputRepository, "repository should be not nil")
	assert.Equal(outputRepository.AccountID, outputRepository.AccountID, "repository name is not correct")
	assert.Equal(outputRepository.Name, outputRepository.Name, "repository name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestPAPDeleteRepositoryWithInvalidAccountID tests the deletion of an repository with an invalid account ID.
func TestPAPDeleteRepositoryWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	repository := &azmodels.Repository{
		RepositoryID: "f2061bdb-3fcb-4561-bef6-04c535c2f5be",
		AccountID: -1,
		Name: "default",
	}
	account, err := storage.DeleteRepository(repository.AccountID, repository.RepositoryID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestPAPDeleteRepositoryWithInvalidRepositoryID tests the deletion of an repository with an invalid repository ID.
func TestPAPDeleteRepositoryWithInvalidRepositoryID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	repository := &azmodels.Repository{
		RepositoryID: "not valid",
		AccountID: 581616507495,
		Name: "default",
	}
	account, err := storage.DeleteRepository(repository.AccountID, repository.RepositoryID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be ErrClientID")
	assert.Nil(account, "accounts should be nil")
}

// TestPAPDeleteANotExistingRepository tests the deletion of an repository that does not exist.
func TestPAPDeleteANotExistingRepository(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	repository, _, _, _ := registerRepositoryForUpdateMocking(account, "businessx")

	accountsSQLSelect := "SELECT .+ FROM \"repositories\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputRepository := &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputRepository, err := storage.DeleteRepository(inputRepository.AccountID, inputRepository.RepositoryID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputRepository, "repository should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

// TestPAPDeleteADefaultRepository tests the deletion of a default repository.
func TestPAPDeleteADefaultRepository(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	repository, _, sqlRepositories, _ := registerRepositoryForUpdateMocking(account, RepositoryDefaultName)

	accountsSQLSelect := "SELECT .+ FROM \"repositories\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlRepositories)

	inputRepository := &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputRepository, err := storage.DeleteRepository(inputRepository.AccountID, inputRepository.RepositoryID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputRepository, "repository should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageNotFound")
}

func TestPAPDeleteAnRepositoryWithAGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	repository, repositoriesSQL, sqlRepositories, _ := registerRepositoryForDeleteMocking(account, "businessx")

	accountsSQLSelect := "SELECT .+ FROM \"repositories\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlRepositories)
	mock.ExpectBegin()
	mock.ExpectExec(repositoriesSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputRepository := &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputRepository, err := storage.DeleteRepository(inputRepository.AccountID, inputRepository.RepositoryID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputRepository, "repository should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageNotFound")
}

// TestPAPDeleteRepositoriesWithSuccess tests the deletion of an repository with success.
func TestPAPDeleteRepositoriesWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	repository, repositoriesSQL, sqlRepositories, sqlRepositoryResult := registerRepositoryForDeleteMocking(account, "businessx")

	accountsSQLSelect := "SELECT .+ FROM \"repositories\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlRepositories)
	mock.ExpectBegin()
	mock.ExpectExec(repositoriesSQL).WillReturnResult(sqlRepositoryResult)
	mock.ExpectCommit()

	inputRepository := &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputRepository, err := storage.DeleteRepository(inputRepository.AccountID, inputRepository.RepositoryID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputRepository, "account should be not nil")
	assert.Equal(outputRepository.RepositoryID, outputRepository.RepositoryID, "account name is not correct")
	assert.Equal(outputRepository.AccountID, outputRepository.AccountID, "account name is not correct")
	assert.Equal(outputRepository.Name, outputRepository.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestPAPGetAllRepositoriesWithInvalidAccountID tests the retrieval of all repositories with an invalid account ID.
func TestPAPGetAllRepositoriesWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	tests := []int64{
		int64(-1),
		int64(0),
	}
	for _, test := range tests {
		account, err := storage.GetAllRepositories(test,nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
		assert.Nil(account, "accounts should be nil")
	}
}

// TestPAPGetAllRepositoriesWithInvalidIdentitySourceID tests the retrieval of all repositories with an invalid repository ID.
func TestPAPGetAllRepositoriesWithInvalidIdentitySourceID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, err := storage.GetAllRepositories(581616507495, map[string]any { azmodels.FieldRepositoryRepositoryID: 1 })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")

	account, err = storage.GetAllRepositories(581616507495, map[string]any { azmodels.FieldRepositoryRepositoryID: "sdfasfd" })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestPAPGetAllRepositoriesWithInvalidIdentitySourceName tests the retrieval of all repositories with an invalid repository name.
func TestPAPGetAllRepositoriesWithInvalidIdentitySourceName(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	account, err := storage.GetAllRepositories(581616507495, map[string]any {
		azmodels.FieldRepositoryRepositoryID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldRepositoryName: 1,
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")

	account, err = storage.GetAllRepositories(581616507495, map[string]any {
		azmodels.FieldRepositoryRepositoryID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldRepositoryName: "a d d",
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

func TestPAPGetAllRepositoriesWithNotExistingRepository(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	repositories, _, _ := registerRepositoryForGetAllMocking()


	accountsSQLSelect := "SELECT .+ FROM \"repositories\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	outputRepository, err := storage.GetAllRepositories(581616507495, map[string]any{
		azmodels.FieldRepositoryRepositoryID: repositories[0].RepositoryID,
		azmodels.FieldRepositoryName: repositories[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputRepository, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

func TestPAPGetAllRepositoriesWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStoragePAPMock(t)
	defer sqlDB.Close()

	repositories, _, sqlRepositories := registerRepositoryForGetAllMocking()

	accountsSQLSelect := "SELECT .+ FROM \"repositories\" WHERE .+"
	mock.ExpectQuery(accountsSQLSelect).WillReturnRows(sqlRepositories)

	outputRepository, err := storage.GetAllRepositories(581616507495, map[string]any{
		azmodels.FieldRepositoryRepositoryID: repositories[0].RepositoryID,
		azmodels.FieldRepositoryName: repositories[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputRepository, "account should be not nil")
	assert.Equal(len(repositories), len(outputRepository), "accounts should be equal")
	for i, account := range outputRepository {
		assert.Equal(account.RepositoryID, outputRepository[i].RepositoryID, "repository id is not correct")
		assert.Equal(account.AccountID, outputRepository[i].AccountID, "repository account id is not correct")
		assert.Equal(account.Name, outputRepository[i].Name, "identity srouce name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
