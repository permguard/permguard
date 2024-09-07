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
	"sort"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"

	"github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azidbtestutils "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerRepositoryForUpsertMocking registers a repository for upsert mocking.
func registerRepositoryForUpsertMocking(isCreate bool) (*Repository, string, *sqlmock.Rows) {
	repository := &Repository{
		RepositoryID: GenerateUUID(),
		AccountID:    581616507495,
		Name:         "rent-a-car",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Refs:         "0000000000000000000000000000000000000000000000000000000000000000",
	}
	var sql string
	if isCreate {
		sql = `INSERT INTO repositories \(account_id, repository_id, name\) VALUES \(\?, \?, \?\)`
	} else {
		sql = `UPDATE repositories SET name = \? WHERE account_id = \? and repository_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"account_id", "repository_id", "created_at", "updated_at", "name", "refs"}).
		AddRow(repository.AccountID, repository.RepositoryID, repository.CreatedAt, repository.UpdatedAt, repository.Name, repository.Name)
	return repository, sql, sqlRows
}

// registerRepositoryForDeleteMocking registers a repository for delete mocking.
func registerRepositoryForDeleteMocking() (string, *Repository, *sqlmock.Rows, string) {
	repository := &Repository{
		RepositoryID: GenerateUUID(),
		AccountID:    581616507495,
		Name:         "rent-a-car",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Refs:         "0000000000000000000000000000000000000000000000000000000000000000",
	}
	var sqlSelect = `SELECT account_id, repository_id, created_at, updated_at, name, refs FROM repositories WHERE account_id = \? and repository_id = \?`
	var sqlDelete = `DELETE FROM repositories WHERE account_id = \? and repository_id = \?`
	sqlRows := sqlmock.NewRows([]string{"account_id", "repository_id", "created_at", "updated_at", "name", "refs"}).
		AddRow(repository.AccountID, repository.RepositoryID, repository.CreatedAt, repository.UpdatedAt, repository.Name, repository.Refs)
	return sqlSelect, repository, sqlRows, sqlDelete
}

// registerRepositoryForFetchMocking registers a repository for fetch mocking.
func registerRepositoryForFetchMocking() (string, []Repository, *sqlmock.Rows) {
	repositories := []Repository{
		{
			RepositoryID: GenerateUUID(),
			AccountID:    581616507495,
			Name:         "rent-a-car",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Refs:         "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	var sqlSelect = "SELECT * FROM repositories WHERE account_id = ? AND repository_id = ? AND name LIKE ? ORDER BY repository_id ASC LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"account_id", "repository_id", "created_at", "updated_at", "name", "refs"}).
		AddRow(repositories[0].AccountID, repositories[0].RepositoryID, repositories[0].CreatedAt, repositories[0].UpdatedAt, repositories[0].Name, repositories[0].Refs)
	return sqlSelect, repositories, sqlRows
}

// TestRepoUpsertRepositoryWithInvalidInput tests the upsert of a repository with invalid input.
func TestRepoUpsertRepositoryWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil repository
		_, err := repo.UpsertRepository(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid account id
		dbInRepository := &Repository{
			RepositoryID: GenerateUUID(),
			Name:         "rent-a-car",
		}
		_, err := repo.UpsertRepository(tx, false, dbInRepository)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid repository id
		dbInRepository := &Repository{
			AccountID: 581616507495,
			Name:      "rent-a-car",
		}
		_, err := repo.UpsertRepository(tx, false, dbInRepository)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid repository name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			repositoryName := test
			_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInRepository := &Repository{
				Name: repositoryName,
			}
			dbOutRepository, err := repo.UpsertRepository(tx, true, dbInRepository)
			assert.NotNil(err, "error should be not nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutRepository, "repository should be nil")
		}
	}
}

// TestRepoUpsertRepositoryWithSuccess tests the upsert of a repository with success.
func TestRepoUpsertRepositoryWithSuccess(t *testing.T) {
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
		repository, sql, sqlRepositoryRows := registerRepositoryForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInRepository *Repository
		if isCreate {
			dbInRepository = &Repository{
				AccountID: repository.AccountID,
				Name:      repository.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(repository.AccountID, sqlmock.AnyArg(), repository.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInRepository = &Repository{
				RepositoryID: repository.RepositoryID,
				AccountID:    repository.AccountID,
				Name:         repository.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(repository.Name, repository.AccountID, repository.RepositoryID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT account_id, repository_id, created_at, updated_at, name, refs FROM repositories WHERE account_id = \? and repository_id = \?`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlRepositoryRows)

		tx, _ := sqlDB.Begin()
		dbOutRepository, err := repo.UpsertRepository(tx, isCreate, dbInRepository)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutRepository, "repository should be not nil")
		assert.Equal(repository.RepositoryID, dbOutRepository.RepositoryID, "repository id is not correct")
		assert.Equal(repository.AccountID, dbOutRepository.AccountID, "repository account id is not correct")
		assert.Equal(repository.Name, dbOutRepository.Name, "repository name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoUpsertRepositoryWithErrors tests the upsert of a repository with errors.
func TestRepoUpsertRepositoryWithErrors(t *testing.T) {
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
		repository, sql, _ := registerRepositoryForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInRepository *Repository
		if isCreate {
			dbInRepository = &Repository{
				AccountID: repository.AccountID,
				Name:      repository.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(repository.AccountID, sqlmock.AnyArg(), repository.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		} else {
			dbInRepository = &Repository{
				RepositoryID: repository.RepositoryID,
				AccountID:    repository.AccountID,
				Name:         repository.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(repository.Name, repository.AccountID, repository.RepositoryID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		}

		tx, _ := sqlDB.Begin()
		dbOutRepository, err := repo.UpsertRepository(tx, isCreate, dbInRepository)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutRepository, "repository should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteRepositoryWithInvalidInput tests the delete of a repository with invalid input.
func TestRepoDeleteRepositoryWithInvalidInput(t *testing.T) {
	repo := Repo{}

	assert := assert.New(t)
	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with invalid account id
		_, err := repo.DeleteRepository(tx, 0, GenerateUUID())
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid repository id
		_, err := repo.DeleteRepository(tx, 581616507495, "")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}

// TestRepoDeleteRepositoryWithSuccess tests the delete of a repository with success.
func TestRepoDeleteRepositoryWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, repository, sqlRepositoryRows, sqlDelete := registerRepositoryForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(repository.AccountID, repository.RepositoryID).
		WillReturnRows(sqlRepositoryRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(repository.AccountID, repository.RepositoryID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutRepository, err := repo.DeleteRepository(tx, repository.AccountID, repository.RepositoryID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutRepository, "repository should be not nil")
	assert.Equal(repository.RepositoryID, dbOutRepository.RepositoryID, "repository id should be correct")
	assert.Equal(repository.AccountID, dbOutRepository.AccountID, "repository account id should be correct")
	assert.Equal(repository.Name, dbOutRepository.Name, "repository name should be correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoDeleteRepositoryWithErrors tests the delete of a repository with errors.
func TestRepoDeleteRepositoryWithErrors(t *testing.T) {
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

		sqlSelect, repository, sqlRepositoryRows, sqlDelete := registerRepositoryForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound})
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(sqlRepositoryRows)
		}

		if test == 2 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrPerm})
		} else if test == 3 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		tx, _ := sqlDB.Begin()
		dbOutRepository, err := repo.DeleteRepository(tx, repository.AccountID, repository.RepositoryID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutRepository, "repository should be nil")
		assert.NotNil(err, "error should be not nil")

		if test == 1 {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be errstoragenotfound")
		} else {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be errstoragegeneric")
		}
	}
}

// TestRepoFetchRepositoryWithInvalidInput tests the fetch of repositories with invalid input.
func TestRepoFetchRepositoryWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{ // Test with invalid page
		_, err := repo.FetchRepositories(sqlDB, 0, 100, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		_, err := repo.FetchRepositories(sqlDB, 1, 0, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid account id
		repositoryID := GenerateUUID()
		_, err := repo.FetchRepositories(sqlDB, 1, 1, 0, &repositoryID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid repository id
		repositoryID := ""
		_, err := repo.FetchRepositories(sqlDB, 1, 1, 581616507495, &repositoryID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid repository name
		repositoryName := "@"
		_, err := repo.FetchRepositories(sqlDB, 1, 1, 581616507495, nil, &repositoryName)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be errclientname")
	}
}

// TestRepoFetchRepositoryWithSuccess tests the fetch of repositories with success.
func TestRepoFetchRepositoryWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlRepositories, sqlRepositoryRows := registerRepositoryForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	repositoryName := "%" + sqlRepositories[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlRepositories[0].AccountID, sqlRepositories[0].RepositoryID, repositoryName, pageSize, page-1).
		WillReturnRows(sqlRepositoryRows)

	dbOutRepository, err := repo.FetchRepositories(sqlDB, page, pageSize, sqlRepositories[0].AccountID, &sqlRepositories[0].RepositoryID, &sqlRepositories[0].Name)

	orderedSQLRepositories := make([]Repository, len(sqlRepositories))
	copy(orderedSQLRepositories, sqlRepositories)
	sort.Slice(orderedSQLRepositories, func(i, j int) bool {
		return orderedSQLRepositories[i].RepositoryID < orderedSQLRepositories[j].RepositoryID
	})

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutRepository, "repository should be not nil")
	assert.Len(orderedSQLRepositories, len(dbOutRepository), "repositories len should be correct")
	for i, repository := range dbOutRepository {
		assert.Equal(repository.RepositoryID, orderedSQLRepositories[i].RepositoryID, "repository id is not correct")
		assert.Equal(repository.AccountID, orderedSQLRepositories[i].AccountID, "repository account id is not correct")
		assert.Equal(repository.Name, orderedSQLRepositories[i].Name, "repository name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
