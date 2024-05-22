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

func TestAAPCreateTenantWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	tenantName := "company-a"
	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tenant := &azmodels.Tenant{
		Name: tenantName,
	}
	account, err := storage.CreateTenant(tenant)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPCreateTenantWithInvalidName tests the creation of an tenant with an invalid name.
func TestAAPCreateTenantWithInvalidName(t *testing.T) {
	assert := assert.New(t)

	tests := []string{
		"",
		" ",
		"@",
		"1aX",
		"X-@x"}
	for _, test := range tests {
		tenantName := test
		storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
		defer sqlDB.Close()

		tenant := &azmodels.Tenant{
			AccountID: 581616507495,
			Name: tenantName,
		}
		outputTenant, err := storage.CreateTenant(tenant)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
		assert.Nil(outputTenant, "accounts should be nil")
	}
}

// TestAAPCreateTenantWithDuplicateError tests the creation of an tenant with a duplicate error.
func TestAAPCreateTenantWithDuplicateError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	tenant, tenantsSQL, _ := registerTenantForInsertMocking(account, "")

	mock.ExpectBegin()
	mock.ExpectQuery(tenantsSQL).WillReturnError(&pgconn.PgError{ Code: "23505" })
	mock.ExpectRollback()

	inputTenant := &azmodels.Tenant{
		AccountID: 581616507495,
		Name: tenant.Name,
	}
	outputTenant, err := storage.CreateTenant(inputTenant)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputTenant, "tenant should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageDuplicate, err), "error should be ErrStorageDuplicate")
}

// TestAAPCreateTenantWithGenericError tests the creation of an tenant with a generic error.
func TestAAPCreateTenantWithGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	tenant, tenantsSQL, _ := registerTenantForInsertMocking(account, "")

	mock.ExpectBegin()
	mock.ExpectQuery(tenantsSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputTenant := &azmodels.Tenant{
		AccountID: 581616507495,
		Name: tenant.Name,
	}
	outputTenant, err := storage.CreateTenant(inputTenant)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputTenant, "tenant should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageGeneric")
}

// TestAAPTenantAccountWithSuccess tests the creation of an tenant with success.
func TestAAPCreateTenantAccountWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _ := registerAccountForInsertMocking()
	tenant, tenantsSQL, sqlTenants := registerTenantForInsertMocking(account, "default")

	mock.ExpectBegin()
	mock.ExpectQuery(tenantsSQL).WillReturnRows(sqlTenants)
	mock.ExpectCommit()

	inputTenant := &azmodels.Tenant{
		AccountID: 581616507495,
		Name: tenant.Name,
	}
	outputTenant, err := storage.CreateTenant(inputTenant)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputTenant, "tenant should be not nil")
	assert.Equal(tenant.AccountID, outputTenant.AccountID, "tenant name is not correct")
	assert.Equal(tenant.Name, outputTenant.Name, "tenant name is not correct")
	assert.Nil(err, "error should be nil")
}

// TestAAPUpdateTenantWithInvalidTenantID tests the update of an tenant with an invalid tenant ID.
func TestAAPUpdateTenantWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tenant := &azmodels.Tenant{
		TenantID: "invalid",
		AccountID: 581616507495,
		Name: "businessx",
	}
	tenant, err := storage.UpdateTenant(tenant)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
	assert.Nil(tenant, "accounts should be nil")
}

// TestAAPUpdateTenantWithInvalidDefaultName tests the update of an tenant with an invalid default name.
func TestAAPUpdateTenantWithInvalidDefaultName(t *testing.T) {
	assert := assert.New(t)

	account, _, _ := registerAccountForInsertMocking()
	tenant, _, _, _ := registerTenantForUpdateMocking(account, "businessx")

	tenantName := TenantDefaultName
	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	inputTenant := &azmodels.Tenant{
		TenantID: tenant.TenantID,
		AccountID: 581616507495,
		Name: tenantName,
	}
	outputTenant, err := storage.UpdateTenant(inputTenant)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientName")
	assert.Nil(outputTenant, "accounts should be nil")
}

// TestAAPUpdateTenantWithSuccess tests the update of an tenant with success.
func TestAAPUpdateTenantWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	tenant, tenantsSQL, sqlTenants, sqlTenantResult := registerTenantForUpdateMocking(account, "businessx")

	tenantsSQLSelect := "SELECT .+ FROM \"tenants\" WHERE .+"
	mock.ExpectQuery(tenantsSQLSelect).WillReturnRows(sqlTenants)
	mock.ExpectBegin()
	mock.ExpectExec(tenantsSQL).WillReturnResult(sqlTenantResult)
	mock.ExpectCommit()

	inputTenant := &azmodels.Tenant{
		TenantID: tenant.TenantID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputTenant, err := storage.UpdateTenant(inputTenant)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputTenant, "tenant should be not nil")
	assert.Equal(outputTenant.AccountID, outputTenant.AccountID, "tenant name is not correct")
	assert.Equal(outputTenant.Name, outputTenant.Name, "tenant name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestAAPDeleteTenantWithInvalidAccountID tests the deletion of an tenant with an invalid account ID.
func TestAAPDeleteTenantWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tenant := &azmodels.Tenant{
		TenantID: "f2061bdb-3fcb-4561-bef6-04c535c2f5be",
		AccountID: -1,
		Name: "default",
	}
	account, err := storage.DeleteTenant(tenant.AccountID, tenant.TenantID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPDeleteTenantWithInvalidTenantID tests the deletion of an tenant with an invalid tenant ID.
func TestAAPDeleteTenantWithInvalidTenantID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tenant := &azmodels.Tenant{
		TenantID: "not valid",
		AccountID: 581616507495,
		Name: "default",
	}
	account, err := storage.DeleteTenant(tenant.AccountID, tenant.TenantID)
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientID, err), "error should be ErrClientID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPDeleteANotExistingTenant tests the deletion of an tenant that does not exist.
func TestAAPDeleteANotExistingTenant(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	tenant, _, _, _ := registerTenantForUpdateMocking(account, "businessx")

	tenantsSQLSelect := "SELECT .+ FROM \"tenants\" WHERE .+"
	mock.ExpectQuery(tenantsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	inputTenant := &azmodels.Tenant{
		TenantID: tenant.TenantID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputTenant, err := storage.DeleteTenant(inputTenant.AccountID, inputTenant.TenantID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputTenant, "tenant should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

// TestAAPDeleteADefaultTenant tests the deletion of a default tenant.
func TestAAPDeleteADefaultTenant(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	tenant, _, sqlTenants, _ := registerTenantForUpdateMocking(account, TenantDefaultName)

	tenantsSQLSelect := "SELECT .+ FROM \"tenants\" WHERE .+"
	mock.ExpectQuery(tenantsSQLSelect).WillReturnRows(sqlTenants)

	inputTenant := &azmodels.Tenant{
		TenantID: tenant.TenantID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputTenant, err := storage.DeleteTenant(inputTenant.AccountID, inputTenant.TenantID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputTenant, "tenant should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageNotFound")
}

func TestAAPDeleteAnTenantWithAGenericError(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	tenant, tenantsSQL, sqlTenants, _ := registerTenantForDeleteMocking(account, "businessx")

	tenantsSQLSelect := "SELECT .+ FROM \"tenants\" WHERE .+"
	mock.ExpectQuery(tenantsSQLSelect).WillReturnRows(sqlTenants)
	mock.ExpectBegin()
	mock.ExpectExec(tenantsSQL).WillReturnError(errors.New("something bad has happened"))
	mock.ExpectRollback()

	inputTenant := &azmodels.Tenant{
		TenantID: tenant.TenantID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputTenant, err := storage.DeleteTenant(inputTenant.AccountID, inputTenant.TenantID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputTenant, "tenant should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageGeneric, err), "error should be ErrStorageNotFound")
}

// TestAAPDeleteTenantsWithSuccess tests the deletion of an tenant with success.
func TestAAPDeleteTenantsWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, _, _, _ := registerAccountForUpdateMocking()
	tenant, tenantsSQL, sqlTenants, sqlTenantResult := registerTenantForDeleteMocking(account, "businessx")

	tenantsSQLSelect := "SELECT .+ FROM \"tenants\" WHERE .+"
	mock.ExpectQuery(tenantsSQLSelect).WillReturnRows(sqlTenants)
	mock.ExpectBegin()
	mock.ExpectExec(tenantsSQL).WillReturnResult(sqlTenantResult)
	mock.ExpectCommit()

	inputTenant := &azmodels.Tenant{
		TenantID: tenant.TenantID,
		AccountID: account.AccountID,
		Name: account.Name,
	}
	outputTenant, err := storage.DeleteTenant(inputTenant.AccountID, inputTenant.TenantID)

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputTenant, "account should be not nil")
	assert.Equal(outputTenant.TenantID, outputTenant.TenantID, "account name is not correct")
	assert.Equal(outputTenant.AccountID, outputTenant.AccountID, "account name is not correct")
	assert.Equal(outputTenant.Name, outputTenant.Name, "account name is not correct")
	assert.Nil(err, "error should be nil")
}


// TestAAPGetAllTenantsWithInvalidAccountID tests the retrieval of all tenants with an invalid account ID.
func TestAAPGetAllTenantsWithInvalidAccountID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tests := []int64{
		int64(-1),
		int64(0),
	}
	for _, test := range tests {
		account, err := storage.GetAllTenants(test,nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, err), "error should be ErrClientAccountID")
		assert.Nil(account, "accounts should be nil")
	}
}

// TestAAPGetAllTenantsWithInvalidIdentitySourceID tests the retrieval of all tenants with an invalid tenant ID.
func TestAAPGetAllTenantsWithInvalidIdentitySourceID(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, err := storage.GetAllTenants(581616507495, map[string]any { azmodels.FieldTenantTenantID: 1 })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")

	account, err = storage.GetAllTenants(581616507495, map[string]any { azmodels.FieldTenantTenantID: "sdfasfd" })
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

// TestAAPGetAllTenantsWithInvalidIdentitySourceName tests the retrieval of all tenants with an invalid tenant name.
func TestAAPGetAllTenantsWithInvalidIdentitySourceName(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, _ := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	account, err := storage.GetAllTenants(581616507495, map[string]any {
		azmodels.FieldTenantTenantID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldTenantName: 1,
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")

	account, err = storage.GetAllTenants(581616507495, map[string]any {
		azmodels.FieldTenantTenantID: "d5608013-f000-41ff-bcec-7cd26a808d18",
		azmodels.FieldTenantName: "a d d",
	})
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, err), "error should be ErrClientAccountID")
	assert.Nil(account, "accounts should be nil")
}

func TestAAPGetAllTenantsWithNotExistingTenant(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tenants, _, _ := registerTenantForGetAllMocking()


	tenantsSQLSelect := "SELECT .+ FROM \"tenants\" WHERE .+"
	mock.ExpectQuery(tenantsSQLSelect).WillReturnError(errors.New("something bad has happened"))

	outputTenant, err := storage.GetAllTenants(581616507495, map[string]any{
		azmodels.FieldTenantTenantID: tenants[0].TenantID,
		azmodels.FieldTenantName: tenants[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(outputTenant, "account should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be ErrStorageNotFound")
}

func TestAAPGetAllTenantsWithSuccess(t *testing.T) {
	assert := assert.New(t)

	storage, sqlDB, _, mock := newPostgresCentralStorageAAPMock(t)
	defer sqlDB.Close()

	tenants, _, sqlTenants := registerTenantForGetAllMocking()


	tenantsSQLSelect := "SELECT .+ FROM \"tenants\" WHERE .+"
	mock.ExpectQuery(tenantsSQLSelect).WillReturnRows(sqlTenants)

	outputTenant, err := storage.GetAllTenants(581616507495, map[string]any{
		azmodels.FieldTenantTenantID: tenants[0].TenantID,
		azmodels.FieldTenantName: tenants[0].Name })

	assert.Nil(mock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(outputTenant, "account should be not nil")
	assert.Equal(len(tenants), len(outputTenant), "accounts should be equal")
	for i, account := range outputTenant {
		assert.Equal(account.TenantID, outputTenant[i].TenantID, "tenant id is not correct")
		assert.Equal(account.AccountID, outputTenant[i].AccountID, "tenant account id is not correct")
		assert.Equal(account.Name, outputTenant[i].Name, "identity srouce name is not correct")
	}
	assert.Nil(err, "error should be nil")
}
