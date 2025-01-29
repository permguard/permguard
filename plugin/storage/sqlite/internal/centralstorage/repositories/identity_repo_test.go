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

// registerIdentityForUpsertMocking registers an identity for upsert mocking.
func registerIdentityForUpsertMocking(isCreate bool) (*Identity, string, *sqlmock.Rows) {
	identity := &Identity{
		IdentityID:       GenerateUUID(),
		ZoneID:           581616507495,
		IdentitySourceID: GenerateUUID(),
		Kind:             1,
		Name:             "nicola.gallo",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	var sql string
	if isCreate {
		sql = `INSERT INTO identities \(zone_id, identity_id, identity_source_id, kind, name\) VALUES \(\?, \?, \?, \?, \?\)`
	} else {
		sql = `UPDATE identities SET kind = \?, name = \? WHERE zone_id = \? and identity_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"zone_id", "identity_id", "created_at", "updated_at", "identity_source_id", "kind", "name"}).
		AddRow(identity.ZoneID, identity.IdentityID, identity.CreatedAt, identity.UpdatedAt, identity.IdentitySourceID, identity.Kind, identity.Name)
	return identity, sql, sqlRows
}

// registerIdentityForDeleteMocking registers an identity for delete mocking.
func registerIdentityForDeleteMocking() (string, *Identity, *sqlmock.Rows, string) {
	identity := &Identity{
		IdentityID:       GenerateUUID(),
		ZoneID:           581616507495,
		IdentitySourceID: GenerateUUID(),
		Kind:             1,
		Name:             "nicola.gallo",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	var sqlSelect = `SELECT zone_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE zone_id = \? and identity_id = \?`
	var sqlDelete = `DELETE FROM identities WHERE zone_id = \? and identity_id = \?`
	sqlRows := sqlmock.NewRows([]string{"zone_id", "identity_id", "created_at", "updated_at", "identity_source_id", "kind", "name"}).
		AddRow(identity.ZoneID, identity.IdentityID, identity.CreatedAt, identity.UpdatedAt, identity.IdentitySourceID, identity.Kind, identity.Name)
	return sqlSelect, identity, sqlRows, sqlDelete
}

// registerIdentityForFetchMocking registers an identity for fetch mocking.
func registerIdentityForFetchMocking() (string, []Identity, *sqlmock.Rows) {
	identities := []Identity{
		{
			IdentityID:       GenerateUUID(),
			ZoneID:           581616507495,
			IdentitySourceID: GenerateUUID(),
			Kind:             1,
			Name:             "nicola.gallo",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		},
	}
	var sqlSelect = "SELECT * FROM identities WHERE zone_id = ? AND identity_id = ? AND name LIKE ? ORDER BY identity_id ASC LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"zone_id", "identity_id", "created_at", "updated_at", "identity_source_id", "kind", "name"}).
		AddRow(identities[0].ZoneID, identities[0].IdentityID, identities[0].CreatedAt, identities[0].UpdatedAt, identities[0].IdentitySourceID, identities[0].Kind, identities[0].Name)
	return sqlSelect, identities, sqlRows
}

// TestRepoUpsertIdentityWithInvalidInput tests the upsert of an identity with invalid input.
func TestRepoUpsertIdentityWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil identity
		_, err := ledger.UpsertIdentity(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid zone id
		dbInIdentity := &Identity{
			IdentityID: GenerateUUID(),
			Name:       "rent-a-car",
		}
		_, err := ledger.UpsertIdentity(tx, false, dbInIdentity)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid identity id
		dbInIdentity := &Identity{
			ZoneID: 581616507495,
			Name:   "rent-a-car",
		}
		_, err := ledger.UpsertIdentity(tx, false, dbInIdentity)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid identity name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			identityName := test
			_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInIdentity := &Identity{
				Name: identityName,
			}
			dbOutIdentity, err := ledger.UpsertIdentity(tx, true, dbInIdentity)
			assert.NotNil(err, "error should be not nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutIdentity, "identity should be nil")
		}
	}
}

// TestRepoUpsertIdentityWithSuccess tests the upsert of an identity with success.
func TestRepoUpsertIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		identity, sql, sqlIdentityRows := registerIdentityForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInIdentity *Identity
		if isCreate {
			dbInIdentity = &Identity{
				ZoneID:           identity.ZoneID,
				IdentitySourceID: identity.IdentitySourceID,
				Kind:             identity.Kind,
				Name:             identity.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identity.ZoneID, sqlmock.AnyArg(), identity.IdentitySourceID, identity.Kind, identity.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInIdentity = &Identity{
				IdentityID:       identity.IdentityID,
				ZoneID:           identity.ZoneID,
				IdentitySourceID: identity.IdentitySourceID,
				Kind:             identity.Kind,
				Name:             identity.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identity.Kind, identity.Name, identity.ZoneID, identity.IdentityID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT zone_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE zone_id = \? and identity_id = \?`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlIdentityRows)

		tx, _ := sqlDB.Begin()
		dbOutIdentity, err := ledger.UpsertIdentity(tx, isCreate, dbInIdentity)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutIdentity, "identity should be not nil")
		assert.Equal(identity.IdentityID, dbOutIdentity.IdentityID, "identity id is not correct")
		assert.Equal(identity.ZoneID, dbOutIdentity.ZoneID, "identity zone id is not correct")
		assert.Equal(identity.IdentitySourceID, dbOutIdentity.IdentitySourceID, "identity source id is not correct")
		assert.Equal(identity.Kind, dbOutIdentity.Kind, "identity kind is not correct")
		assert.Equal(identity.Name, dbOutIdentity.Name, "identity name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoUpsertIdentityWithErrors tests the upsert of an identity with errors.
func TestRepoUpsertIdentityWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	tests := []bool{
		true,
		false,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		isCreate := test
		identity, sql, _ := registerIdentityForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInIdentity *Identity
		if isCreate {
			dbInIdentity = &Identity{
				ZoneID:           identity.ZoneID,
				IdentitySourceID: identity.IdentitySourceID,
				Kind:             identity.Kind,
				Name:             identity.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identity.ZoneID, sqlmock.AnyArg(), identity.IdentitySourceID, identity.Kind, identity.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		} else {
			dbInIdentity = &Identity{
				IdentityID:       identity.IdentityID,
				ZoneID:           identity.ZoneID,
				IdentitySourceID: identity.IdentitySourceID,
				Kind:             identity.Kind,
				Name:             identity.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(identity.Kind, identity.Name, identity.ZoneID, identity.IdentityID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		}

		tx, _ := sqlDB.Begin()
		dbOutIdentity, err := ledger.UpsertIdentity(tx, isCreate, dbInIdentity)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutIdentity, "identity should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteIdentityWithInvalidInput tests the delete of an identity with invalid input.
func TestRepoDeleteIdentityWithInvalidInput(t *testing.T) {
	ledger := Repository{}

	assert := assert.New(t)
	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with invalid zone id
		_, err := ledger.DeleteIdentity(tx, 0, GenerateUUID())
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid identity id
		_, err := ledger.DeleteIdentity(tx, 581616507495, "")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}

// TestRepoDeleteIdentityWithSuccess tests the delete of an identity with success.
func TestRepoDeleteIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, identity, sqlIdentityRows, sqlDelete := registerIdentityForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(identity.ZoneID, identity.IdentityID).
		WillReturnRows(sqlIdentityRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(identity.ZoneID, identity.IdentityID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutIdentity, err := ledger.DeleteIdentity(tx, identity.ZoneID, identity.IdentityID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutIdentity, "identity should be not nil")
	assert.Equal(identity.IdentityID, dbOutIdentity.IdentityID, "identity id is not correct")
	assert.Equal(identity.ZoneID, dbOutIdentity.ZoneID, "identity zone id is not correct")
	assert.Equal(identity.IdentitySourceID, dbOutIdentity.IdentitySourceID, "identity source id is not correct")
	assert.Equal(identity.Kind, dbOutIdentity.Kind, "identity kind is not correct")
	assert.Equal(identity.Name, dbOutIdentity.Name, "identity name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoDeleteIdentityWithErrors tests the delete of an identity with errors.
func TestRepoDeleteIdentityWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	tests := []int{
		1,
		2,
		3,
	}
	for _, test := range tests {
		_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
		defer sqlDB.Close()

		sqlSelect, identity, sqlIdentityRows, sqlDelete := registerIdentityForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound})
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(sqlIdentityRows)
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
		dbOutIdentity, err := ledger.DeleteIdentity(tx, identity.ZoneID, identity.IdentityID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutIdentity, "identity should be nil")
		assert.NotNil(err, "error should be not nil")

		if test == 1 {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be errstoragenotfound")
		} else {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be errstoragegeneric")
		}
	}
}

// TestRepoFetchIdentityWithInvalidInput tests the fetch of identities with invalid input.
func TestRepoFetchIdentityWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{ // Test with invalid page
		_, err := ledger.FetchIdentities(sqlDB, 0, 100, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		_, err := ledger.FetchIdentities(sqlDB, 1, 0, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid zone id
		identityID := GenerateUUID()
		_, err := ledger.FetchIdentities(sqlDB, 1, 1, 0, &identityID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid identity id
		identityID := ""
		_, err := ledger.FetchIdentities(sqlDB, 1, 1, 581616507495, &identityID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid identity name
		identityName := "@"
		_, err := ledger.FetchIdentities(sqlDB, 1, 1, 581616507495, nil, &identityName)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be errclientname")
	}
}

// TestRepoFetchIdentityWithSuccess tests the fetch of identities with success.
func TestRepoFetchIdentityWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlIdentities, sqlIdentityRows := registerIdentityForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	identityName := "%" + sqlIdentities[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlIdentities[0].ZoneID, sqlIdentities[0].IdentityID, identityName, pageSize, page-1).
		WillReturnRows(sqlIdentityRows)

	dbOutIdentities, err := ledger.FetchIdentities(sqlDB, page, pageSize, sqlIdentities[0].ZoneID, &sqlIdentities[0].IdentityID, &sqlIdentities[0].Name)

	orderedSQLIdentities := make([]Identity, len(sqlIdentities))
	copy(orderedSQLIdentities, sqlIdentities)
	sort.Slice(orderedSQLIdentities, func(i, j int) bool {
		return orderedSQLIdentities[i].IdentityID < orderedSQLIdentities[j].IdentityID
	})

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutIdentities, "identity should be not nil")
	assert.Len(orderedSQLIdentities, len(dbOutIdentities), "identities len should be correct")
	for i, identity := range dbOutIdentities {
		assert.Equal(identity.IdentityID, orderedSQLIdentities[i].IdentityID, "identity id is not correct")
		assert.Equal(identity.ZoneID, orderedSQLIdentities[i].ZoneID, "identity zone id is not correct")
		assert.Equal(identity.IdentitySourceID, orderedSQLIdentities[i].IdentitySourceID, "identity source id is not correct")
		assert.Equal(identity.Kind, orderedSQLIdentities[i].Kind, "identity kind is not correct")
		assert.Equal(identity.Name, orderedSQLIdentities[i].Name, "identity name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
