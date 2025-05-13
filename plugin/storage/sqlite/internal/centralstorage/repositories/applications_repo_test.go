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
	"errors"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"

	"github.com/mattn/go-sqlite3"

	"github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerZoneForUpsertMocking registers a zone for upsert mocking.
func registerZoneForUpsertMocking(isCreate bool) (*Zone, string, *sqlmock.Rows) {
	zone := &Zone{
		ZoneID:    581616507495,
		Name:      "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	var sql string
	if isCreate {
		sql = `INSERT INTO zones \(zone_id, name\) VALUES \(\?, \?\)`
	} else {
		sql = `UPDATE zones SET name = \? WHERE zone_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"zone_id", "created_at", "updated_at", "name"}).
		AddRow(zone.ZoneID, zone.CreatedAt, zone.UpdatedAt, zone.Name)
	return zone, sql, sqlRows
}

// registerZoneForDeleteMocking registers a zone for delete mocking.
func registerZoneForDeleteMocking() (string, *Zone, *sqlmock.Rows, string) {
	zone := &Zone{
		ZoneID:    581616507495,
		Name:      "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	var sqlSelect = `SELECT zone_id, created_at, updated_at, name FROM zones WHERE zone_id = \?`
	var sqlDelete = `DELETE FROM zones WHERE zone_id = \?`
	sqlRows := sqlmock.NewRows([]string{"zone_id", "created_at", "updated_at", "name"}).
		AddRow(zone.ZoneID, zone.CreatedAt, zone.UpdatedAt, zone.Name)
	return sqlSelect, zone, sqlRows, sqlDelete
}

// registerZoneForFetchMocking registers a zone for fetch mocking.
func registerZoneForFetchMocking() (string, []Zone, *sqlmock.Rows) {
	zones := []Zone{
		{
			ZoneID:    581616507495,
			Name:      "rent-a-car",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	var sqlSelect = "SELECT * FROM zones WHERE zone_id = ? AND name LIKE ? ORDER BY zone_id ASC LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"zone_id", "created_at", "updated_at", "name"}).
		AddRow(zones[0].ZoneID, zones[0].CreatedAt, zones[0].UpdatedAt, zones[0].Name)
	return sqlSelect, zones, sqlRows
}

// TestRepoUpsertZoneWithInvalidInput tests the upsert of a zone with invalid input.
func TestRepoUpsertZoneWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil zone
		_, err := ledger.UpsertZone(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
	}

	{ // Test with invalid zone id
		dbInZone := &Zone{
			ZoneID: 0,
			Name:   "rent-a-car",
		}
		_, err := ledger.UpsertZone(tx, false, dbInZone)
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
	}

	{ // Test with invalid zone name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			zoneName := test
			_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInZone := &Zone{
				Name: zoneName,
			}
			dbOutZone, err := ledger.UpsertZone(tx, true, dbInZone)
			assert.NotNil(err, "error should be not nil")
			assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
			assert.Nil(dbOutZone, "zones should be nil")
		}
	}
}

// TestRepoUpsertZoneWithSuccess tests the upsert of a zone with success.
func TestRepoUpsertZoneWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		zone, sql, sqlZoneRows := registerZoneForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInZone *Zone
		if isCreate {
			dbInZone = &Zone{
				Name: zone.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), zone.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInZone = &Zone{
				ZoneID: zone.ZoneID,
				Name:   zone.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(zone.Name, zone.ZoneID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT zone_id, created_at, updated_at, name FROM zones WHERE zone_id = \?`).
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(sqlZoneRows)

		tx, _ := sqlDB.Begin()
		dbOutZone, err := ledger.UpsertZone(tx, isCreate, dbInZone)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutZone, "zone should be not nil")
		assert.Equal(zone.ZoneID, dbOutZone.ZoneID, "zone id is not correct")
		assert.Equal(zone.Name, dbOutZone.Name, "zone name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoCreateZoneWithSuccess tests the upsert of a zone with success.
func TestRepoUpsertZoneWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		zone, sql, _ := registerZoneForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInZone *Zone
		if isCreate {
			dbInZone = &Zone{
				Name: zone.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), zone.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		} else {
			dbInZone = &Zone{
				ZoneID: zone.ZoneID,
				Name:   zone.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(zone.Name, zone.ZoneID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		}

		tx, _ := sqlDB.Begin()
		dbOutZone, err := ledger.UpsertZone(tx, isCreate, dbInZone)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutZone, "zone should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteZoneWithInvalidInput tests the delete of a zone with invalid input.
func TestRepoDeleteZoneWithInvalidInput(t *testing.T) {
	ledger := Repository{}

	assert := assert.New(t)
	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with invalid zone id
		_, err := ledger.DeleteZone(tx, 0)
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientparameter")
	}
}

// TestRepoDeleteZoneWithSuccess tests the delete of a zone with success.
func TestRepoDeleteZoneWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, zone, sqlZoneRows, sqlDelete := registerZoneForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(zone.ZoneID).
		WillReturnRows(sqlZoneRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(zone.ZoneID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutZone, err := ledger.DeleteZone(tx, zone.ZoneID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutZone, "zone should be not nil")
	assert.Equal(zone.ZoneID, dbOutZone.ZoneID, "zone id is not correct")
	assert.Equal(zone.Name, dbOutZone.Name, "zone name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoDeleteZoneWithErrors tests the delete of a zone with errors.
func TestRepoDeleteZoneWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	tests := []int{
		1,
		2,
		3,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		sqlSelect, zone, sqlZoneRows, sqlDelete := registerZoneForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound})
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnRows(sqlZoneRows)
		}

		switch test {
		case 2:
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrPerm})
		case 3:
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		tx, _ := sqlDB.Begin()
		dbOutZone, err := ledger.DeleteZone(tx, zone.ZoneID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutZone, "zone should be nil")
		assert.NotNil(err, "error should be not nil")

		if test == 1 {
			assert.True(errors.Is(errors.New("operation error"), err), "error should be errstoragenotfound")
		} else {
			assert.True(errors.Is(errors.New("operation error"), err), "error should be errstoragegeneric")
		}
	}
}

// TestRepoFetchZoneWithInvalidInput tests the fetch of zones with invalid input.
func TestRepoFetchZoneWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{ // Test with invalid page
		_, err := ledger.FetchZones(sqlDB, 0, 100, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		_, err := ledger.FetchZones(sqlDB, 1, 0, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientpagination")
	}

	{ // Test with invalid zone id
		zoneID := int64(0)
		_, err := ledger.FetchZones(sqlDB, 1, 1, &zoneID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientid")
	}

	{ // Test with invalid zone id
		zoneName := "@"
		_, err := ledger.FetchZones(sqlDB, 1, 1, nil, &zoneName)
		assert.NotNil(err, "error should be not nil")
		assert.True(errors.Is(errors.New("operation error"), err), "error should be errclientname")
	}
}

// TestRepoFetchZoneWithSuccess tests the fetch of zones with success.
func TestRepoFetchZoneWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlZones, sqlZoneRows := registerZoneForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	zoneName := "%" + sqlZones[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlZones[0].ZoneID, zoneName, pageSize, page-1).
		WillReturnRows(sqlZoneRows)

	dbOutZone, err := ledger.FetchZones(sqlDB, page, pageSize, &sqlZones[0].ZoneID, &sqlZones[0].Name)

	orderedSQLZones := make([]Zone, len(sqlZones))
	copy(orderedSQLZones, sqlZones)
	sort.Slice(orderedSQLZones, func(i, j int) bool {
		return orderedSQLZones[i].ZoneID < orderedSQLZones[j].ZoneID
	})

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutZone, "zone should be not nil")
	assert.Len(orderedSQLZones, len(dbOutZone), "zones len should be correct")
	for i, zone := range dbOutZone {
		assert.Equal(zone.ZoneID, orderedSQLZones[i].ZoneID, "zone id is not correct")
		assert.Equal(zone.Name, orderedSQLZones[i].Name, "zone name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
