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
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azidbtestutils "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerTenantForUpsertMocking registers an tenant for upsert mocking.
func registerTenantForUpsertMocking(isCreate bool) (*Tenant, string, *sqlmock.Rows) {
	tenant := &Tenant{
		TenantID: uuid.New().String(),
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	var sql string
	if isCreate {
		sql =`INSERT INTO tenants \(tenant_id, name\) VALUES \(\?, \?\)`
	} else {
		sql = `UPDATE tenants SET name = \? WHERE tenant_id = \?`
	}
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "created_at", "updated_at", "name"}).
		AddRow(tenant.TenantID, tenant.CreatedAt, tenant.UpdatedAt, tenant.Name)
	return tenant, sql, sqlRows
}

// registerTenantForDeleteMocking registers an tenant for delete mocking.
func registerTenantForDeleteMocking() (string, *Tenant, *sqlmock.Rows, string) {
	tenant := &Tenant{
		TenantID: uuid.New().String(),
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	var sqlSelect = `SELECT tenant_id, created_at, updated_at, name FROM tenants WHERE tenant_id = \?`
	var sqlDelete = `DELETE FROM tenants WHERE tenant_id = \?`
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "created_at", "updated_at", "name"}).
		AddRow(tenant.TenantID, tenant.CreatedAt, tenant.UpdatedAt, tenant.Name)
	return sqlSelect, tenant, sqlRows, sqlDelete
}

// registerTenantForFetchMocking registers an tenant for fetch mocking.
func registerTenantForFetchMocking() (string, []Tenant, *sqlmock.Rows) {
	tenants := []Tenant {
		{
			TenantID: uuid.New().String(),
			AccountID: 581616507495,
			Name: "rent-a-car",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	var sqlSelect = "SELECT * FROM tenants WHERE tenant_id = ? AND name LIKE ? ORDER BY tenant_id LIMIT ? OFFSET ?"
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "created_at", "updated_at", "name"}).
		AddRow(tenants[0].TenantID, tenants[0].CreatedAt, tenants[0].UpdatedAt, tenants[0].Name)
	return sqlSelect, tenants, sqlRows
}

// TestRepoUpsertTenantWithInvalidInput tests the upsert of an tenant with invalid input.
func TestRepoUpsertTenantWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{	// Test with nil tenant
		_, err := repo.UpsertTenant(tx, true, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{	// Test with invalid tenant id
		dbInTenant := &Tenant{
			Name: "rent-a-car",
		}
		_, err := repo.UpsertTenant(tx, false, dbInTenant)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ 	// Test with invalid tenant name
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
			dbOutTenant, err := repo.UpsertTenant(tx, true, dbInTenant)
			assert.NotNil(err, "error should be not nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
			assert.Nil(dbOutTenant, "tenants should be nil")
		}
	}
}

// TestRepoUpsertTenantWithSuccess tests the upsert of an tenant with success.
func TestRepoUpsertTenantWithSuccess(t *testing.T) {
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
		tenant, sql, sqlTenantRows := registerTenantForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()
		var dbInTenant *Tenant
		if isCreate {
			dbInTenant = &Tenant{
				Name: tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), tenant.Name).
				WillReturnResult(sqlmock.NewResult(1, 1))
		} else {
			dbInTenant = &Tenant{
				TenantID: tenant.TenantID,
				Name: tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(tenant.Name, tenant.TenantID).
				WillReturnResult(sqlmock.NewResult(1, 1))
		}

		sqlDBMock.ExpectQuery(`SELECT tenant_id, created_at, updated_at, name FROM tenants WHERE tenant_id = \?`).
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(sqlTenantRows)


		tx, _ := sqlDB.Begin()
		dbOutTenant, err := repo.UpsertTenant(tx, isCreate, dbInTenant)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.NotNil(dbOutTenant, "tenant should be not nil")
		assert.Equal(tenant.TenantID, dbOutTenant.TenantID, "tenant name is not correct")
		assert.Equal(tenant.Name, dbOutTenant.Name, "tenant name is not correct")
		assert.Nil(err, "error should be nil")
	}
}

// TestRepoCreateTenantWithSuccess tests the upsert of an tenant with success.
func TestRepoUpsertTenantWithErrors(t *testing.T) {
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
		tenant, sql, _ := registerTenantForUpsertMocking(isCreate)

		sqlDBMock.ExpectBegin()

		var dbInTenant *Tenant
		if isCreate {
			dbInTenant = &Tenant{
				Name: tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(sqlmock.AnyArg(), tenant.Name).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique })
		} else {
			dbInTenant = &Tenant{
				TenantID: tenant.TenantID,
				Name: tenant.Name,
			}
			sqlDBMock.ExpectExec(sql).
				WithArgs(tenant.Name, tenant.TenantID).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique })
		}

		tx, _ := sqlDB.Begin()
		dbOutTenant, err := repo.UpsertTenant(tx, isCreate, dbInTenant)

		assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
		assert.Nil(dbOutTenant, "tenant should be nil")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
	}
}

// TestRepoDeleteTenantWithInvalidInput tests the delete of an tenant with invalid input.
func TestRepoDeleteTenantWithInvalidInput(t *testing.T) {
	repo := Repo{}

	assert := assert.New(t)
	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{	// Test with invalid tenant id
		_, err := repo.DeleteTenant(tx, "")
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}


// TestRepoDeleteTenantWithSuccess tests the delete of an tenant with success.
func TestRepoDeleteTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, tenant, sqlTenantRows, sqlDelete := registerTenantForDeleteMocking()

	sqlDBMock.ExpectBegin()

	sqlDBMock.ExpectQuery(sqlSelect).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlTenantRows)

	sqlDBMock.ExpectExec(sqlDelete).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, _ := sqlDB.Begin()
	dbOutTenant, err := repo.DeleteTenant(tx, tenant.TenantID)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutTenant, "tenant should be not nil")
	assert.Equal(tenant.TenantID, dbOutTenant.TenantID, "tenant name is not correct")
	assert.Equal(tenant.Name, dbOutTenant.Name, "tenant name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestRepoDeleteTenantWithErrors tests the delete of an tenant with errors.
func TestRepoDeleteTenantWithErrors(t *testing.T) {
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

		sqlSelect, tenant, sqlTenantRows, sqlDelete := registerTenantForDeleteMocking()

		sqlDBMock.ExpectBegin()

		if test == 1 {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrNotFound })
		} else {
			sqlDBMock.ExpectQuery(sqlSelect).
				WithArgs(sqlmock.AnyArg()).
				WillReturnRows(sqlTenantRows)
		}

		if test == 2 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(sqlite3.Error{Code: sqlite3.ErrPerm })
		} else if test == 3 {
			sqlDBMock.ExpectExec(sqlDelete).
				WithArgs(sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}

		tx, _ := sqlDB.Begin()
		dbOutTenant, err := repo.DeleteTenant(tx, tenant.TenantID)

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
	repo := Repo{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	{	// Test with invalid page
		_, err := repo.FetchTenants(sqlDB, 0, 100, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid page size
		_, err := repo.FetchTenants(sqlDB, 1, 0, nil, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientPagination, err), "error should be errclientpagination")
	}

	{	// Test with invalid tenant id
		tenantID := ""
		_, err := repo.FetchTenants(sqlDB, 1, 1, &tenantID, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be errclientid")
	}

	{	// Test with invalid tenant id
		tenantName := "@"
		_, err := repo.FetchTenants(sqlDB, 1, 1, nil, &tenantName)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be errclientname")
	}
}

// TestRepoFetchTenantWithSuccess tests the fetch of tenants with success.
func TestRepoFetchTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Repo{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlSelect, sqlTenants, sqlTenantRows := registerTenantForFetchMocking()

	page := int32(1)
	pageSize := int32(100)
	tenantName := "%" + sqlTenants[0].Name + "%"
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlSelect)).
		WithArgs(sqlTenants[0].TenantID, tenantName, pageSize, page - 1).
		WillReturnRows(sqlTenantRows)

	dbOutTenant, err := repo.FetchTenants(sqlDB, page, pageSize, &sqlTenants[0].TenantID, &sqlTenants[0].Name)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutTenant, "tenant should be not nil")
	assert.Len(dbOutTenant, len(sqlTenants), "tenants len should be correct")
	for i, tenant := range dbOutTenant {
		assert.Equal(tenant.TenantID, sqlTenants[i].TenantID, "tenant name is not correct")
		assert.Equal(tenant.Name, sqlTenants[i].Name, "tenant name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
