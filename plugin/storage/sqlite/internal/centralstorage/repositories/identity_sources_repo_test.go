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

	"github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerIdentitySourceForUpsertMocking registers an identity source for upsert mocking.
func registerIdentitySourceForUpsertMocking(isCreate bool) (*IdentitySource, string, *sqlmock.Rows) {
	identitySource := &IdentitySource{
		IdentitySourceID: GenerateUUID(),
		ZoneID:           581616507495,
		Name:             "rent-a-car",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	var sql string
	if isCreate {
		sql = `INSERT INTO identity_sources \(zone_id, identity_source_id, name\) VALUES \(\?, \?, \?\)`
	} else {
		sql = `UPDATE identity_sources SET name = \? WHERE zone_id = \? and identity_source_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"zone_id", "identity_source_id", "created_at", "updated_at", "name"}).
		AddRow(identitySource.ZoneID, identitySource.IdentitySourceID, identitySource.CreatedAt, identitySource.UpdatedAt, identitySource.Name)
	return identitySource, sql, sqlRows
}

// registerIdentitySourceForDeleteMocking registers an identity source for delete mocking.
func registerIdentitySourceForDeleteMocking() (string, *IdentitySource, *sqlmock.Rows, string) {
	identitySource := &IdentitySource{
		IdentitySourceID: GenerateUUID(),
		ZoneID:           581616507495,
		Name:             "rent-a-car",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	var sqlSelect = `SELECT zone_id, identity_source_id, created_at, updated_at, name FROM identity_sources WHERE zone_id = \? and identity_source_id = \?`
	var sqlDelete = `DELETE FROM identity_sources WHERE zone_id = \? and identity_source_id = \?`
	sqlRows := sqlmock.NewRows([]string{"zone_id", "identity_source_id", "created_at", "updated_at", "name"}).
		AddRow(identitySource.ZoneID, identitySource.IdentitySourceID, identitySource.CreatedAt, identitySource.UpdatedAt, identitySource.Name)
	return sqlSelect, identitySource, sqlRows, sqlDelete
}

// registerIdentitySourceForFetchMocking registers an identity source for fetch mocking.
func registerIdentitySourceForFetchMocking() (string, []IdentitySource, *sqlmock.Rows) {
	identitySources := []IdentitySource{
		{
			IdentitySourceID: GenerateUUID(),
			ZoneID:           581616507495,
			Name:             "rent-a-car",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
	}
	var sqlSelect = "SELECT * FROM identity_sources WHERE zone_id = ? AND identity_source_id = ? AND name LIKE ? ORDER BY identity_source_id ASC LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"zone_id", "identity_source_id", "created_at", "updated_at", "name"}).
		AddRow(identitySources[0].ZoneID, identitySources[0].IdentitySourceID, identitySources[0].CreatedAt, identitySources[0].UpdatedAt, identitySources[0].Name)
	return sqlSelect, identitySources, sqlRows
}

// TestRepoUpsertIdentitySourceWithInvalidInput tests the upsert of an identity source with invalid input.
func TestRepoUpsertIdentitySourceWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil identity source
		_, err := ledger.UpsertIdentitySource(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid zone id
		dbInIdentitySource := &IdentitySource{
			IdentitySourceID: GenerateUUID(),
			Name:             "rent-a-car",
		}
		_, err := ledger.UpsertIdentitySource(tx, false, dbInIdentitySource)
		assert.NotNil(err, "error should be not nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid identity source id
		dbInIdentitySource := &IdentitySource{
			ZoneID: 581616507495,
			Name:   "rent-a-car",
		}
		_, err := ledger.UpsertIdentitySource(tx, false, dbInIdentitySource)
		assert.NotNil(err, "error should be not nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid identity source name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			identitySourceName := test
			_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInIdentitySource := &IdentitySource{
				Name: identitySourceName,
			}
			dbOutIdentitySource, err := ledger.UpsertIdentitySource(tx, true, dbInIdentitySource)
			assert.NotNil(err, "error should be not nil")
			assert.NotNil(err, "error should not be nil")
			assert.Nil(dbOutIdentitySource, "identity sources should be nil")
		}
	}
}

// TestRepoUpsertIdentitySourceWithSuccess tests the upsert of an identity source with success.
func TestRepoUpsertIdentitySourceWithSuccess(t *testing.T) {
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
		identitySource, sql, sqlIdentitySourceRows := registerIdentitySourceForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInIdentitySource *IdentitySource
		if isCreate {
			dbInIdentitySource = &IdentitySource{
				ZoneID: identitySource.ZoneID,
				Name:   identitySource.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identitySource.ZoneID, sqlmock.AnyArg(), identitySource.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInIdentitySource = &IdentitySource{
				IdentitySourceID: identitySource.IdentitySourceID,
				ZoneID:           identitySource.ZoneID,
				Name:             identitySource.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identitySource.Name, identitySource.ZoneID, identitySource.IdentitySourceID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT zone_id, identity_source_id, created_at, updated_at, name FROM identity_sources WHERE zone_id = \? and identity_source_id = \?`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlIdentitySourceRows)

		tx, _ := sqlDB.Begin()
		dbOutIdentitySource, err := ledger.UpsertIdentitySource(tx, isCreate, dbInIdentitySource)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutIdentitySource, "identity source should be not nil")
		assert.Equal(identitySource.IdentitySourceID, dbOutIdentitySource.IdentitySourceID, "identity source id is not correct")
		assert.Equal(identitySource.ZoneID, dbOutIdentitySource.ZoneID, "identity source zone id is not correct")
		assert.Equal(identitySource.Name, dbOutIdentitySource.Name, "identity source name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoUpsertIdentitySourceWithErrors tests the upsert of an identity source with errors.
func TestRepoUpsertIdentitySourceWithErrors(t *testing.T) {
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
		identitySource, sql, _ := registerIdentitySourceForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInIdentitySource *IdentitySource
		if isCreate {
			dbInIdentitySource = &IdentitySource{
				ZoneID: identitySource.ZoneID,
				Name:   identitySource.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identitySource.ZoneID, sqlmock.AnyArg(), identitySource.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		} else {
			dbInIdentitySource = &IdentitySource{
				IdentitySourceID: identitySource.IdentitySourceID,
				ZoneID:           identitySource.ZoneID,
				Name:             identitySource.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identitySource.Name, identitySource.ZoneID, identitySource.IdentitySourceID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		}

		tx, _ := sqlDB.Begin()
		dbOutIdentitySource, err := ledger.UpsertIdentitySource(tx, isCreate, dbInIdentitySource)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutIdentitySource, "identity source should be nil")
		assert.NotNil(err, "error should be not nil")
	}
}

// TestRepoDeleteIdentitySourceWithInvalidInput tests the delete of an identity source with invalid input.
func TestRepoDeleteIdentitySourceWithInvalidInput(t *testing.T) {
	ledger := Repository{}

	assert := assert.New(t)
	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with invalid zone id
		_, err := ledger.DeleteIdentitySource(tx, 0, GenerateUUID())
		assert.NotNil(err, "error should be not nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with invalid identity source id
		_, err := ledger.DeleteIdentitySource(tx, 581616507495, "")
		assert.NotNil(err, "error should be not nil")
		assert.NotNil(err, "error should not be nil")
	}
}

// TestRepoDeleteIdentitySourceWithSuccess tests the delete of an identity source with success.
func TestRepoDeleteIdentitySourceWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, identitySource, sqlIdentitySourceRows, sqlDelete := registerIdentitySourceForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(identitySource.ZoneID, identitySource.IdentitySourceID).
		WillReturnRows(sqlIdentitySourceRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(identitySource.ZoneID, identitySource.IdentitySourceID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutIdentitySource, err := ledger.DeleteIdentitySource(tx, identitySource.ZoneID, identitySource.IdentitySourceID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutIdentitySource, "identity source should be not nil")
	assert.Equal(identitySource.IdentitySourceID, dbOutIdentitySource.IdentitySourceID, "identity source id is not correct")
	assert.Equal(identitySource.ZoneID, dbOutIdentitySource.ZoneID, "identity source zone id is not correct")
	assert.Equal(identitySource.Name, dbOutIdentitySource.Name, "identity source name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoDeleteIdentitySourceWithErrors tests the delete of an identity source with errors.
func TestRepoDeleteIdentitySourceWithErrors(t *testing.T) {
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

		sqlSelect, identitySource, sqlIdentitySourceRows, sqlDelete := registerIdentitySourceForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound})
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(sqlIdentitySourceRows)
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
		dbOutIdentitySource, err := ledger.DeleteIdentitySource(tx, identitySource.ZoneID, identitySource.IdentitySourceID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutIdentitySource, "identity source should be nil")
		assert.NotNil(err, "error should be not nil")
	}
}

// TestRepoFetchIdentitySourceWithInvalidInput tests the fetch of identity sources with invalid input.
func TestRepoFetchIdentitySourceWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{ // Test with invalid page
		_, err := ledger.FetchIdentitySources(sqlDB, 0, 100, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
	}

	{ // Test with invalid page size
		_, err := ledger.FetchIdentitySources(sqlDB, 1, 0, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
	}

	{ // Test with invalid zone id
		identitySourceID := GenerateUUID()
		_, err := ledger.FetchIdentitySources(sqlDB, 1, 1, 0, &identitySourceID, nil)
		assert.NotNil(err, "error should be not nil")
	}

	{ // Test with invalid identity source id
		identitySourceID := ""
		_, err := ledger.FetchIdentitySources(sqlDB, 1, 1, 581616507495, &identitySourceID, nil)
		assert.NotNil(err, "error should be not nil")
	}

	{ // Test with invalid identity source name
		identitySourceName := "@"
		_, err := ledger.FetchIdentitySources(sqlDB, 1, 1, 581616507495, nil, &identitySourceName)
		assert.NotNil(err, "error should be not nil")
	}
}

// TestRepoFetchIdentitySourceWithSuccess tests the fetch of identity sources with success.
func TestRepoFetchIdentitySourceWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlIdentitySources, sqlIdentitySourceRows := registerIdentitySourceForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	identitySourceName := "%" + sqlIdentitySources[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlIdentitySources[0].ZoneID, sqlIdentitySources[0].IdentitySourceID, identitySourceName, pageSize, page-1).
		WillReturnRows(sqlIdentitySourceRows)

	dbOutIdentitySource, err := ledger.FetchIdentitySources(sqlDB, page, pageSize, sqlIdentitySources[0].ZoneID, &sqlIdentitySources[0].IdentitySourceID, &sqlIdentitySources[0].Name)

	orderedSQLIdentitySources := make([]IdentitySource, len(sqlIdentitySources))
	copy(orderedSQLIdentitySources, sqlIdentitySources)
	sort.Slice(orderedSQLIdentitySources, func(i, j int) bool {
		return orderedSQLIdentitySources[i].IdentitySourceID < orderedSQLIdentitySources[j].IdentitySourceID
	})

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutIdentitySource, "identity source should be not nil")
	assert.Len(orderedSQLIdentitySources, len(dbOutIdentitySource), "identity sources len should be correct")
	for i, identitySource := range dbOutIdentitySource {
		assert.Equal(identitySource.IdentitySourceID, orderedSQLIdentitySources[i].IdentitySourceID, "identity source id is not correct")
		assert.Equal(identitySource.ZoneID, orderedSQLIdentitySources[i].ZoneID, "identity source zone id is not correct")
		assert.Equal(identitySource.Name, orderedSQLIdentitySources[i].Name, "identity source name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
