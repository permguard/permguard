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

package facade

import (
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"

	"github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azidbtestutils "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/facade/testutils"
)

// registerApplicationForUpsertMocking registers an application for upsert mocking.
func registerApplicationForUpsertMocking(isCreate bool) (*Application, string, *sqlmock.Rows) {
	application := &Application{
		ApplicationID: 581616507495,
		Name:          "rent-a-car",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	var sql string
	if isCreate {
		sql = `INSERT INTO applications \(application_id, name\) VALUES \(\?, \?\)`
	} else {
		sql = `UPDATE applications SET name = \? WHERE application_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"application_id", "created_at", "updated_at", "name"}).
		AddRow(application.ApplicationID, application.CreatedAt, application.UpdatedAt, application.Name)
	return application, sql, sqlRows
}

// registerApplicationForDeleteMocking registers an application for delete mocking.
func registerApplicationForDeleteMocking() (string, *Application, *sqlmock.Rows, string) {
	application := &Application{
		ApplicationID: 581616507495,
		Name:          "rent-a-car",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	var sqlSelect = `SELECT application_id, created_at, updated_at, name FROM applications WHERE application_id = \?`
	var sqlDelete = `DELETE FROM applications WHERE application_id = \?`
	sqlRows := sqlmock.NewRows([]string{"application_id", "created_at", "updated_at", "name"}).
		AddRow(application.ApplicationID, application.CreatedAt, application.UpdatedAt, application.Name)
	return sqlSelect, application, sqlRows, sqlDelete
}

// registerApplicationForFetchMocking registers an application for fetch mocking.
func registerApplicationForFetchMocking() (string, []Application, *sqlmock.Rows) {
	applications := []Application{
		{
			ApplicationID: 581616507495,
			Name:          "rent-a-car",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}
	var sqlSelect = "SELECT * FROM applications WHERE application_id = ? AND name LIKE ? ORDER BY application_id ASC LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"application_id", "created_at", "updated_at", "name"}).
		AddRow(applications[0].ApplicationID, applications[0].CreatedAt, applications[0].UpdatedAt, applications[0].Name)
	return sqlSelect, applications, sqlRows
}

// TestRepoUpsertApplicationWithInvalidInput tests the upsert of an application with invalid input.
func TestRepoUpsertApplicationWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil application
		_, err := ledger.UpsertApplication(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid application id
		dbInApplication := &Application{
			ApplicationID: 0,
			Name:          "rent-a-car",
		}
		_, err := ledger.UpsertApplication(tx, false, dbInApplication)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid application name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			applicationName := test
			_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInApplication := &Application{
				Name: applicationName,
			}
			dbOutApplication, err := ledger.UpsertApplication(tx, true, dbInApplication)
			assert.NotNil(err, "error should be not nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutApplication, "applications should be nil")
		}
	}
}

// TestRepoUpsertApplicationWithSuccess tests the upsert of an application with success.
func TestRepoUpsertApplicationWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		application, sql, sqlApplicationRows := registerApplicationForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInApplication *Application
		if isCreate {
			dbInApplication = &Application{
				Name: application.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), application.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInApplication = &Application{
				ApplicationID: application.ApplicationID,
				Name:          application.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(application.Name, application.ApplicationID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT application_id, created_at, updated_at, name FROM applications WHERE application_id = \?`).
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(sqlApplicationRows)

		tx, _ := sqlDB.Begin()
		dbOutApplication, err := ledger.UpsertApplication(tx, isCreate, dbInApplication)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutApplication, "application should be not nil")
		assert.Equal(application.ApplicationID, dbOutApplication.ApplicationID, "application id is not correct")
		assert.Equal(application.Name, dbOutApplication.Name, "application name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoCreateApplicationWithSuccess tests the upsert of an application with success.
func TestRepoUpsertApplicationWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		application, sql, _ := registerApplicationForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInApplication *Application
		if isCreate {
			dbInApplication = &Application{
				Name: application.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), application.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		} else {
			dbInApplication = &Application{
				ApplicationID: application.ApplicationID,
				Name:          application.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(application.Name, application.ApplicationID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		}

		tx, _ := sqlDB.Begin()
		dbOutApplication, err := ledger.UpsertApplication(tx, isCreate, dbInApplication)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutApplication, "application should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteApplicationWithInvalidInput tests the delete of an application with invalid input.
func TestRepoDeleteApplicationWithInvalidInput(t *testing.T) {
	ledger := Facade{}

	assert := assert.New(t)
	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with invalid application id
		_, err := ledger.DeleteApplication(tx, 0)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}

// TestRepoDeleteApplicationWithSuccess tests the delete of an application with success.
func TestRepoDeleteApplicationWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, application, sqlApplicationRows, sqlDelete := registerApplicationForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(application.ApplicationID).
		WillReturnRows(sqlApplicationRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(application.ApplicationID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutApplication, err := ledger.DeleteApplication(tx, application.ApplicationID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutApplication, "application should be not nil")
	assert.Equal(application.ApplicationID, dbOutApplication.ApplicationID, "application id is not correct")
	assert.Equal(application.Name, dbOutApplication.Name, "application name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoDeleteApplicationWithErrors tests the delete of an application with errors.
func TestRepoDeleteApplicationWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	tests := []int{
		1,
		2,
		3,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		sqlSelect, application, sqlApplicationRows, sqlDelete := registerApplicationForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound})
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnRows(sqlApplicationRows)
		}

		if test == 2 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrPerm})
		} else if test == 3 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		tx, _ := sqlDB.Begin()
		dbOutApplication, err := ledger.DeleteApplication(tx, application.ApplicationID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutApplication, "application should be nil")
		assert.NotNil(err, "error should be not nil")

		if test == 1 {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be errstoragenotfound")
		} else {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be errstoragegeneric")
		}
	}
}

// TestRepoFetchApplicationWithInvalidInput tests the fetch of applications with invalid input.
func TestRepoFetchApplicationWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{ // Test with invalid page
		_, err := ledger.FetchApplications(sqlDB, 0, 100, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		_, err := ledger.FetchApplications(sqlDB, 1, 0, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid application id
		applicationID := int64(0)
		_, err := ledger.FetchApplications(sqlDB, 1, 1, &applicationID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid application id
		applicationName := "@"
		_, err := ledger.FetchApplications(sqlDB, 1, 1, nil, &applicationName)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be errclientname")
	}
}

// TestRepoFetchApplicationWithSuccess tests the fetch of applications with success.
func TestRepoFetchApplicationWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlApplications, sqlApplicationRows := registerApplicationForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	applicationName := "%" + sqlApplications[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlApplications[0].ApplicationID, applicationName, pageSize, page-1).
		WillReturnRows(sqlApplicationRows)

	dbOutApplication, err := ledger.FetchApplications(sqlDB, page, pageSize, &sqlApplications[0].ApplicationID, &sqlApplications[0].Name)

	orderedSQLApplications := make([]Application, len(sqlApplications))
	copy(orderedSQLApplications, sqlApplications)
	sort.Slice(orderedSQLApplications, func(i, j int) bool {
		return orderedSQLApplications[i].ApplicationID < orderedSQLApplications[j].ApplicationID
	})

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutApplication, "application should be not nil")
	assert.Len(orderedSQLApplications, len(dbOutApplication), "applications len should be correct")
	for i, application := range dbOutApplication {
		assert.Equal(application.ApplicationID, orderedSQLApplications[i].ApplicationID, "application id is not correct")
		assert.Equal(application.Name, orderedSQLApplications[i].Name, "application name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
