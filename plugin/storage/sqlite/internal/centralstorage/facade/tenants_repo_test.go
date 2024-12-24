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

// registerTenantForUpsertMocking registers an tenant for upsert mocking.
func registerTenantForUpsertMocking(isCreate bool) (*Tenant, string, *sqlmock.Rows) {
	tenant := &Tenant{
		TenantID:      GenerateUUID(),
		ApplicationID: 581616507495,
		Name:          "rent-a-car",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	var sql string
	if isCreate {
		sql = `INSERT INTO tenants \(application_id, tenant_id, name\) VALUES \(\?, \?, \?\)`
	} else {
		sql = `UPDATE tenants SET name = \? WHERE application_id = \? and tenant_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"application_id", "tenant_id", "created_at", "updated_at", "name"}).
		AddRow(tenant.ApplicationID, tenant.TenantID, tenant.CreatedAt, tenant.UpdatedAt, tenant.Name)
	return tenant, sql, sqlRows
}

// registerTenantForDeleteMocking registers an tenant for delete mocking.
func registerTenantForDeleteMocking() (string, *Tenant, *sqlmock.Rows, string) {
	tenant := &Tenant{
		TenantID:      GenerateUUID(),
		ApplicationID: 581616507495,
		Name:          "rent-a-car",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	var sqlSelect = `SELECT application_id, tenant_id, created_at, updated_at, name FROM tenants WHERE application_id = \? and tenant_id = \?`
	var sqlDelete = `DELETE FROM tenants WHERE application_id = \? and tenant_id = \?`
	sqlRows := sqlmock.NewRows([]string{"application_id", "tenant_id", "created_at", "updated_at", "name"}).
		AddRow(tenant.ApplicationID, tenant.TenantID, tenant.CreatedAt, tenant.UpdatedAt, tenant.Name)
	return sqlSelect, tenant, sqlRows, sqlDelete
}

// registerTenantForFetchMocking registers an tenant for fetch mocking.
func registerTenantForFetchMocking() (string, []Tenant, *sqlmock.Rows) {
	tenants := []Tenant{
		{
			TenantID:      GenerateUUID(),
			ApplicationID: 581616507495,
			Name:          "rent-a-car",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}
	var sqlSelect = "SELECT * FROM tenants WHERE application_id = ? AND tenant_id = ? AND name LIKE ? ORDER BY tenant_id ASC LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"application_id", "tenant_id", "created_at", "updated_at", "name"}).
		AddRow(tenants[0].ApplicationID, tenants[0].TenantID, tenants[0].CreatedAt, tenants[0].UpdatedAt, tenants[0].Name)
	return sqlSelect, tenants, sqlRows
}

// TestRepoUpsertTenantWithInvalidInput tests the upsert of an tenant with invalid input.
func TestRepoUpsertTenantWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil tenant
		_, err := ledger.UpsertTenant(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid application id
		dbInTenant := &Tenant{
			TenantID: GenerateUUID(),
			Name:     "rent-a-car",
		}
		_, err := ledger.UpsertTenant(tx, false, dbInTenant)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid tenant id
		dbInTenant := &Tenant{
			ApplicationID: 581616507495,
			Name:          "rent-a-car",
		}
		_, err := ledger.UpsertTenant(tx, false, dbInTenant)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid tenant name
		tests := []string{
			"",
			" ",
			"@",
			"1aX",
			"X-@x"}
		for _, test := range tests {
			tenantName := test
			_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
			defer sqlDB.Close()

			tx, _ := sqlDB.Begin()

			dbInTenant := &Tenant{
				Name: tenantName,
			}
			dbOutTenant, err := ledger.UpsertTenant(tx, true, dbInTenant)
			assert.NotNil(err, "error should be not nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutTenant, "tenants should be nil")
		}
	}
}

// TestRepoUpsertTenantWithSuccess tests the upsert of an tenant with success.
func TestRepoUpsertTenantWithSuccess(t *testing.T) {
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
		tenant, sql, sqlTenantRows := registerTenantForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInTenant *Tenant
		if isCreate {
			dbInTenant = &Tenant{
				ApplicationID: tenant.ApplicationID,
				Name:          tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(tenant.ApplicationID, sqlmock.AnyArg(), tenant.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInTenant = &Tenant{
				TenantID:      tenant.TenantID,
				ApplicationID: tenant.ApplicationID,
				Name:          tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(tenant.Name, tenant.ApplicationID, tenant.TenantID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT application_id, tenant_id, created_at, updated_at, name FROM tenants WHERE application_id = \? and tenant_id = \?`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlTenantRows)

		tx, _ := sqlDB.Begin()
		dbOutTenant, err := ledger.UpsertTenant(tx, isCreate, dbInTenant)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutTenant, "tenant should be not nil")
		assert.Equal(tenant.TenantID, dbOutTenant.TenantID, "tenant tenant id is not correct")
		assert.Equal(tenant.ApplicationID, dbOutTenant.ApplicationID, "tenant application id is not correct")
		assert.Equal(tenant.Name, dbOutTenant.Name, "tenant name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoCreateTenantWithSuccess tests the upsert of an tenant with success.
func TestRepoUpsertTenantWithErrors(t *testing.T) {
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
		tenant, sql, _ := registerTenantForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInTenant *Tenant
		if isCreate {
			dbInTenant = &Tenant{
				ApplicationID: tenant.ApplicationID,
				Name:          tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(tenant.ApplicationID, sqlmock.AnyArg(), tenant.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		} else {
			dbInTenant = &Tenant{
				TenantID:      tenant.TenantID,
				ApplicationID: tenant.ApplicationID,
				Name:          tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(tenant.Name, tenant.ApplicationID, tenant.TenantID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})
		}

		tx, _ := sqlDB.Begin()
		dbOutTenant, err := ledger.UpsertTenant(tx, isCreate, dbInTenant)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutTenant, "tenant should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteTenantWithInvalidInput tests the delete of an tenant with invalid input.
func TestRepoDeleteTenantWithInvalidInput(t *testing.T) {
	ledger := Facade{}

	assert := assert.New(t)
	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with invalid application id
		_, err := ledger.DeleteTenant(tx, 0, GenerateUUID())
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with invalid tenant id
		_, err := ledger.DeleteTenant(tx, 581616507495, "")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}

// TestRepoDeleteTenantWithSuccess tests the delete of an tenant with success.
func TestRepoDeleteTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, tenant, sqlTenantRows, sqlDelete := registerTenantForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(tenant.ApplicationID, tenant.TenantID).
		WillReturnRows(sqlTenantRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(tenant.ApplicationID, tenant.TenantID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutTenant, err := ledger.DeleteTenant(tx, tenant.ApplicationID, tenant.TenantID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutTenant, "tenant should be not nil")
	assert.Equal(tenant.TenantID, dbOutTenant.TenantID, "tenant id is not correct")
	assert.Equal(tenant.ApplicationID, dbOutTenant.ApplicationID, "tenant application id is not correct")
	assert.Equal(tenant.Name, dbOutTenant.Name, "tenant name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoDeleteTenantWithErrors tests the delete of an tenant with errors.
func TestRepoDeleteTenantWithErrors(t *testing.T) {
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

		sqlSelect, tenant, sqlTenantRows, sqlDelete := registerTenantForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound})
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(sqlTenantRows)
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
		dbOutTenant, err := ledger.DeleteTenant(tx, tenant.ApplicationID, tenant.TenantID)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutTenant, "tenant should be nil")
		assert.NotNil(err, "error should be not nil")

		if test == 1 {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be errstoragenotfound")
		} else {
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be errstoragegeneric")
		}
	}
}

// TestRepoFetchTenantWithInvalidInput tests the fetch of tenants with invalid input.
func TestRepoFetchTenantWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{ // Test with invalid page
		_, err := ledger.FetchTenants(sqlDB, 0, 100, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid page size
		_, err := ledger.FetchTenants(sqlDB, 1, 0, 581616507495, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{ // Test with invalid application id
		tenantID := GenerateUUID()
		_, err := ledger.FetchTenants(sqlDB, 1, 1, 0, &tenantID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid tenant id
		tenantID := ""
		_, err := ledger.FetchTenants(sqlDB, 1, 1, 581616507495, &tenantID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{ // Test with invalid tenant id
		tenantName := "@"
		_, err := ledger.FetchTenants(sqlDB, 1, 1, 581616507495, nil, &tenantName)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be errclientname")
	}
}

// TestRepoFetchTenantWithSuccess tests the fetch of tenants with success.
func TestRepoFetchTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Facade{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlTenants, sqlTenantRows := registerTenantForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	tenantName := "%" + sqlTenants[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlTenants[0].ApplicationID, sqlTenants[0].TenantID, tenantName, pageSize, page-1).
		WillReturnRows(sqlTenantRows)

	dbOutTenant, err := ledger.FetchTenants(sqlDB, page, pageSize, sqlTenants[0].ApplicationID, &sqlTenants[0].TenantID, &sqlTenants[0].Name)

	orderedSQLTenants := make([]Tenant, len(sqlTenants))
	copy(orderedSQLTenants, sqlTenants)
	sort.Slice(orderedSQLTenants, func(i, j int) bool {
		return orderedSQLTenants[i].TenantID < orderedSQLTenants[j].TenantID
	})

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutTenant, "tenant should be not nil")
	assert.Len(orderedSQLTenants, len(dbOutTenant), "tenants len should be correct")
	for i, tenant := range dbOutTenant {
		assert.Equal(tenant.TenantID, orderedSQLTenants[i].TenantID, "tenant id is not correct")
		assert.Equal(tenant.ApplicationID, orderedSQLTenants[i].ApplicationID, "tenant application id is not correct")
		assert.Equal(tenant.Name, orderedSQLTenants[i].Name, "tenant name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
