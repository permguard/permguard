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

	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerLedgerForUpsertMocking registers a ledger for upsert mocking.
func registerLedgerForUpsertMocking(isCreate bool) (*Ledger, string, *sqlmock.Rows) {
	ledger := &Ledger{
		LedgerID:  GenerateUUID(),
		ZoneID:    581616507495,
		Name:      "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Kind:      1,
		Ref:       "0000000000000000000000000000000000000000000000000000000000000000",
	}
	var sql string
	if isCreate {
		sql = `INSERT INTO ledgers \(zone_id, ledger_id, kind, name\) VALUES \(\?, \?, \?, \?\)`
	} else {
		sql = `UPDATE ledgers SET name = \? WHERE zone_id = \? and ledger_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"zone_id", "ledger_id", "created_at", "updated_at", "kind", "name", "ref"}).
		AddRow(ledger.ZoneID, ledger.LedgerID, ledger.CreatedAt, ledger.UpdatedAt, ledger.Kind, ledger.Name, ledger.Ref)
	return ledger, sql, sqlRows
}

// registerLedgerForDeleteMocking registers a ledger for delete mocking.
func registerLedgerForDeleteMocking() (string, *Ledger, *sqlmock.Rows, string) {
	ledger := &Ledger{
		LedgerID:  GenerateUUID(),
		ZoneID:    581616507495,
		Name:      "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Kind:      1,
		Ref:       "0000000000000000000000000000000000000000000000000000000000000000",
	}
	var sqlSelect = `SELECT zone_id, ledger_id, created_at, updated_at, kind, name, ref FROM ledgers WHERE zone_id = \? and ledger_id = \?`
	var sqlDelete = `DELETE FROM ledgers WHERE zone_id = \? and ledger_id = \?`
	sqlRows := sqlmock.NewRows([]string{"zone_id", "ledger_id", "created_at", "updated_at", "kind", "name", "ref"}).
		AddRow(ledger.ZoneID, ledger.LedgerID, ledger.CreatedAt, ledger.UpdatedAt, ledger.Kind, ledger.Name, ledger.Ref)
	return sqlSelect, ledger, sqlRows, sqlDelete
}

// registerLedgerForFetchMocking registers a ledger for fetch mocking.
func registerLedgerForFetchMocking() (string, []Ledger, *sqlmock.Rows) {
	ledgers := []Ledger{
		{
			LedgerID:  GenerateUUID(),
			ZoneID:    581616507495,
			Name:      "rent-a-car",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Kind:      1,
			Ref:       "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	var sqlSelect = "SELECT * FROM ledgers WHERE zone_id = ? AND ledger_id = ? AND name LIKE ? ORDER BY ledger_id ASC LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"zone_id", "ledger_id", "created_at", "updated_at", "kind", "name", "ref"}).
		AddRow(ledgers[0].ZoneID, ledgers[0].LedgerID, ledgers[0].CreatedAt, ledgers[0].UpdatedAt, ledgers[0].Kind, ledgers[0].Name, ledgers[0].Ref)
	return sqlSelect, ledgers, sqlRows
}

// TestRepoUpsertLedgerWithInvalidInput tests the upsert of a ledger with invalid input.
func TestRepoUpsertLedgerWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil ledger
		_, err := ledger.UpsertLedger(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid zone id
		dbInLedger := &Ledger{
			LedgerID: GenerateUUID(),
			Name:     "rent-a-car",
		}
		_, err := ledger.UpsertLedger(tx, false, dbInLedger)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid ledger id
		dbInLedger := &Ledger{
			ZoneID: 581616507495,
			Name:   "rent-a-car",
		}
		_, err := ledger.UpsertLedger(tx, false, dbInLedger)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid ledger name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			ledgerName := test
			_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInLedger := &Ledger{
				Name: ledgerName,
			}
			dbOutLedger, err := ledger.UpsertLedger(tx, true, dbInLedger)
			assert.NotNil(err, "error should be not nil")
			assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutLedger, "ledger should be nil")
		}
	}
}

// TestRepoUpsertLedgerWithSuccess tests the upsert of a ledger with success.
func TestRepoUpsertLedgerWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repository := Repository{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		ledger, sql, sqlLedgerRows := registerLedgerForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInLedger *Ledger
		if isCreate {
			dbInLedger = &Ledger{
				ZoneID: ledger.ZoneID,
				Name:   ledger.Name,
				Kind:   1,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(ledger.ZoneID, sqlmock.AnyArg(), ledger.Kind, ledger.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInLedger = &Ledger{
				LedgerID: ledger.LedgerID,
				ZoneID:   ledger.ZoneID,
				Name:     ledger.Name,
				Kind:     1,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(ledger.Name, ledger.ZoneID, ledger.LedgerID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT zone_id, ledger_id, created_at, updated_at, kind, name, ref FROM ledgers WHERE zone_id = \? and ledger_id = \?`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlLedgerRows)

		tx, _ := sqlDB.Begin()
		dbOutLedger, err := repository.UpsertLedger(tx, isCreate, dbInLedger)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutLedger, "ledger should be not nil")
		assert.Equal(ledger.LedgerID, dbOutLedger.LedgerID, "ledger id is not correct")
		assert.Equal(ledger.ZoneID, dbOutLedger.ZoneID, "ledger zone id is not correct")
		assert.Equal(ledger.Name, dbOutLedger.Name, "ledger name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoUpsertLedgerWithErrors tests the upsert of a ledger with errors.
func TestRepoUpsertLedgerWithErrors(t *testing.T) {
	assert := assert.New(t)
	repository := Repository{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		ledger, sql, _ := registerLedgerForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInLedger *Ledger
		if isCreate {
			dbInLedger = &Ledger{
				ZoneID: ledger.ZoneID,
				Name:   ledger.Name,
				Kind:   1,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(ledger.ZoneID, sqlmock.AnyArg(), ledger.Kind, ledger.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		} else {
			dbInLedger = &Ledger{
				LedgerID: ledger.LedgerID,
				ZoneID:   ledger.ZoneID,
				Name:     ledger.Name,
				Kind:     1,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(ledger.Name, ledger.ZoneID, ledger.LedgerID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		}

		tx, _ := sqlDB.Begin()
		dbOutLedger, err := repository.UpsertLedger(tx, isCreate, dbInLedger)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutLedger, "ledger should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteLedgerWithInvalidInput tests the delete of a ledger with invalid input.
func TestRepoDeleteLedgerWithInvalidInput(t *testing.T) {
	ledger := Repository{}

	assert := assert.New(t)
	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with invalid zone id
		_, err := ledger.DeleteLedger(tx, 0, GenerateUUID())
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid ledger id
		_, err := ledger.DeleteLedger(tx, 581616507495, "")
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}

// TestRepoDeleteLedgerWithSuccess tests the delete of a ledger with success.
func TestRepoDeleteLedgerWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repository := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, ledger, sqlLedgerRows, sqlDelete := registerLedgerForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(ledger.ZoneID, ledger.LedgerID).
		WillReturnRows(sqlLedgerRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(ledger.ZoneID, ledger.LedgerID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutLedger, err := repository.DeleteLedger(tx, ledger.ZoneID, ledger.LedgerID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutLedger, "ledger should be not nil")
	assert.Equal(ledger.LedgerID, dbOutLedger.LedgerID, "ledger id should be correct")
	assert.Equal(ledger.ZoneID, dbOutLedger.ZoneID, "ledger zone id should be correct")
	assert.Equal(ledger.Name, dbOutLedger.Name, "ledger name should be correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoDeleteLedgerWithErrors tests the delete of a ledger with errors.
func TestRepoDeleteLedgerWithErrors(t *testing.T) {
	assert := assert.New(t)
	repository := Repository{}

	tests := []int{
		1,
		2,
		3,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		sqlSelect, ledger, sqlLedgerRows, sqlDelete := registerLedgerForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound})
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(sqlLedgerRows)
		}

		switch test {
		case 2:
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrPerm})
		case 3:
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		tx, _ := sqlDB.Begin()
		dbOutLedger, err := repository.DeleteLedger(tx, ledger.ZoneID, ledger.LedgerID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutLedger, "ledger should be nil")
		assert.NotNil(err, "error should be not nil")

		if test == 1 {
			assert.True(cerrors.AreErrorsEqual(cerrors.ErrStorageNotFound, err), "error should be errstoragenotfound")
		} else {
			assert.True(cerrors.AreErrorsEqual(cerrors.ErrStorageGeneric, err), "error should be errstoragegeneric")
		}
	}
}

// TestRepoFetchLedgerWithInvalidInput tests the fetch of ledgers with invalid input.
func TestRepoFetchLedgerWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{ // Test with invalid page
		_, err := ledger.FetchLedgers(sqlDB, 0, 100, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		_, err := ledger.FetchLedgers(sqlDB, 1, 0, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid zone id
		ledgerID := GenerateUUID()
		_, err := ledger.FetchLedgers(sqlDB, 1, 1, 0, &ledgerID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid ledger id
		ledgerID := ""
		_, err := ledger.FetchLedgers(sqlDB, 1, 1, 581616507495, &ledgerID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid ledger name
		ledgerName := "@"
		_, err := ledger.FetchLedgers(sqlDB, 1, 1, 581616507495, nil, &ledgerName)
		assert.NotNil(err, "error should be not nil")
		assert.True(cerrors.AreErrorsEqual(cerrors.ErrClientName, err), "error should be errclientname")
	}
}

// TestRepoFetchLedgerWithSuccess tests the fetch of ledgers with success.
func TestRepoFetchLedgerWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlLedgers, sqlLedgerRows := registerLedgerForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	ledgerName := "%" + sqlLedgers[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlLedgers[0].ZoneID, sqlLedgers[0].LedgerID, ledgerName, pageSize, page-1).
		WillReturnRows(sqlLedgerRows)

	dbOutLedger, err := ledger.FetchLedgers(sqlDB, page, pageSize, sqlLedgers[0].ZoneID, &sqlLedgers[0].LedgerID, &sqlLedgers[0].Name)

	orderedSQLLedgers := make([]Ledger, len(sqlLedgers))
	copy(orderedSQLLedgers, sqlLedgers)
	sort.Slice(orderedSQLLedgers, func(i, j int) bool {
		return orderedSQLLedgers[i].LedgerID < orderedSQLLedgers[j].LedgerID
	})

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutLedger, "ledger should be not nil")
	assert.Len(orderedSQLLedgers, len(dbOutLedger), "ledgers len should be correct")
	for i, ledger := range dbOutLedger {
		assert.Equal(ledger.LedgerID, orderedSQLLedgers[i].LedgerID, "ledger id is not correct")
		assert.Equal(ledger.ZoneID, orderedSQLLedgers[i].ZoneID, "ledger zone id is not correct")
		assert.Equal(ledger.Name, orderedSQLLedgers[i].Name, "ledger name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
