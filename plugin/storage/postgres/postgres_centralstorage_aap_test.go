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
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azrtmmocks "github.com/permguard/permguard/pkg/agents/runtime/mocks"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// newPostgresCentralStorageAAPMock creates a new AAPCentralStorage with a mock sql.DB and gorm.DB.
func newPostgresCentralStorageAAPMock(t *testing.T) (azstorage.AAPCentralStorage, *sql.DB, *gorm.DB, sqlmock.Sqlmock) {
	runtimeCtx := azrtmmocks.NewRuntimeContextMock()
	storageCtx, err := azstorage.NewStorageContext(runtimeCtx, azstorage.StoragePostgres)
	if err != nil {
		t.Fatal(err)
	}
	pgConn, sqlDB, gormDB, mock := newPostgresConnectionMock(t)
	storage, err := newPostgresCentralStorage(storageCtx, pgConn)
	if err != nil {
		t.Fatal(err)
	}
	aapStorage, err := storage.GetAAPCentralStorage()
	if err != nil {
		t.Fatal(err)
	}
	return aapStorage, sqlDB, gormDB, mock
}

// registerAccountForInsertMocking registers an account for insert mocking.
func registerAccountForInsertMocking() (*azmodels.Account, string, *sqlmock.Rows) {
	account := &azmodels.Account{
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sql := "INSERT INTO \"accounts\" (.+) VALUES (.+)"
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"}).
		AddRow(account.AccountID, account.CreatedAt, account.UpdatedAt, account.Name)
	return account, sql, sqlRows
}

// registerAccountForUpdateMocking registers an account for update mocking.
func registerAccountForUpdateMocking() (*azmodels.Account, string, *sqlmock.Rows, driver.Result) {
	account := &azmodels.Account{
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sql := "UPDATE \"accounts\" .+"
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"}).
		AddRow(account.AccountID, account.CreatedAt, account.UpdatedAt, account.Name)
	sqlResult := sqlmock.NewResult(account.AccountID, 1)
	return account, sql, sqlRows, sqlResult
}

// registerAccountForDeleteMocking registers an account for delete mocking.
func registerAccountForDeleteMocking() (*azmodels.Account, string, *sqlmock.Rows, driver.Result) {
	account := &azmodels.Account{
		AccountID: 581616507495,
		Name: "rent-a-car",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	sql := "DELETE FROM \"accounts\" WHERE \"accounts\".\"account_id\" = .+"
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"}).
		AddRow(account.AccountID, account.CreatedAt, account.UpdatedAt, account.Name)
	sqlResult := sqlmock.NewResult(account.AccountID, 1)
	return account, sql, sqlRows, sqlResult
}

// registerAccountForGetAllMocking  registers accounts for get all mocking.
func registerAccountForGetAllMocking() ([]azmodels.Account, string, *sqlmock.Rows) {
	accounts := []azmodels.Account {
		{
			AccountID: 581616507495,
			Name: "rent-a-car",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			AccountID: 673389447445,
			Name: "book-a-lesson",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	sql := "SELECT .+ FROM \"accounts\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"account_id", "created_at", "updated_at", "name"})
	for _, account := range accounts {
		sqlRows  = sqlRows.AddRow(account.AccountID, account.CreatedAt, account.UpdatedAt, account.Name)
	}
	return accounts, sql, sqlRows
}

// registerTenantsForInsertMocking registers tenants for insert mocking.
func registerTenantsForInsertMocking(account *azmodels.Account, name string) (*azmodels.Tenant, string, *sqlmock.Rows) {
	tenant := &azmodels.Tenant{
		TenantID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "INSERT INTO \"tenants\" (.+) VALUES (.+)"
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "created_at", "updated_at", "account_id", "name"}).
		AddRow(tenant.TenantID, tenant.CreatedAt, tenant.UpdatedAt, tenant.AccountID, tenant.Name)
	return tenant, sql, sqlRows
}

// registerIdentitySourceForInsertMocking registers an identity source for insert mocking.
func registerIdentitySourceForInsertMocking(account *azmodels.Account, name string) (*azmodels.IdentitySource, string, *sqlmock.Rows) {
	if name == "" {
		name = "authx"
	}
	identitySource := &azmodels.IdentitySource{
		IdentitySourceID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "INSERT INTO \"identity_sources\" (.+) VALUES (.+)"
	sqlRows := sqlmock.NewRows([]string{"identity_source_id", "created_at", "updated_at", "account_id", "name"}).
		AddRow(identitySource.IdentitySourceID, identitySource.CreatedAt, identitySource.UpdatedAt, identitySource.AccountID, identitySource.Name)
	return identitySource, sql, sqlRows
}

// registerIdentitySourceForUpdateMocking register an identity source for update mocking.
func registerIdentitySourceForUpdateMocking(account *azmodels.Account, name string) (*azmodels.IdentitySource, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "authx"
	}
	identitySource := &azmodels.IdentitySource{
		IdentitySourceID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "UPDATE \"identity_sources\" .+"
	sqlRows := sqlmock.NewRows([]string{"identity_Source_id", "account_id", "created_at", "updated_at", "name"}).
		AddRow(identitySource.IdentitySourceID, identitySource.AccountID, identitySource.CreatedAt, identitySource.UpdatedAt, identitySource.Name)
	sqlResult := sqlmock.NewResult(identitySource.AccountID, 1)
	return identitySource, sql, sqlRows, sqlResult
}

// registerIdentitySourceForDeleteMocking register an identity source for delete mocking.
func registerIdentitySourceForDeleteMocking(account *azmodels.Account, name string) (*azmodels.IdentitySource, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "authx"
	}
	identitySource := &azmodels.IdentitySource{
		IdentitySourceID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "DELETE FROM \"identity_sources\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"identity_Source_id", "account_id", "created_at", "updated_at", "name"}).
		AddRow(identitySource.IdentitySourceID, identitySource.AccountID, identitySource.CreatedAt, identitySource.UpdatedAt, identitySource.Name)
	sqlResult := sqlmock.NewResult(identitySource.AccountID, 1)
	return identitySource, sql, sqlRows, sqlResult
}

// registerIdentitySourceForGetAllMocking registers the mocking for the GetAll method of the IdentitySourceRepository
func registerIdentitySourceForGetAllMocking() ([]azmodels.IdentitySource, string, *sqlmock.Rows) {
	identitySources := []azmodels.IdentitySource {
		{
			IdentitySourceID: "1609037a-0c69-4568-ba2a-792f90fc000f",
			AccountID: 581616507495,
			Name: "authx1",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			IdentitySourceID: "24f378b2-f12f-4a45-90a2-81bfa7e98229",
			AccountID: 673389447445,
			Name: "authx2",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	sql := "SELECT .+ FROM \"identity_sources\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"identity_source_id", "created_at", "updated_at", "account_id", "name"})
	for _, identitySource := range identitySources {
		sqlRows  = sqlRows.AddRow(identitySource.IdentitySourceID, identitySource.CreatedAt, identitySource.UpdatedAt, identitySource.AccountID, identitySource.Name)
	}
	return identitySources, sql, sqlRows
}

// registerIdentityForInsertMocking registers an identity for insert mocking.
func registerIdentityForInsertMocking(account *azmodels.Account, name string) (*azmodels.Identity, string, *sqlmock.Rows) {
	if name == "" {
		name = "nicola"
	}
	identity := &azmodels.Identity{
		IdentityID: uuid.New().String(),
		IdentitySourceID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Kind: "user",
		Name: name,
	}
	sql := "INSERT INTO \"identities\" (.+) VALUES (.+)"
	identityKind, _ := convertIdentityKindToID(identity.Kind)
	sqlRows := sqlmock.NewRows([]string{"identity_id", "identity_source_id", "created_at", "updated_at", "account_id", "kind", "name"}).
		AddRow(identity.IdentityID, identity.IdentitySourceID, identity.CreatedAt, identity.UpdatedAt, identity.AccountID, identityKind, identity.Name)
	return identity, sql, sqlRows
}

// registerIdentityForUpdateMocking register an identity for update mocking.
func registerIdentityForUpdateMocking(account *azmodels.Account, name string) (*azmodels.Identity, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "nicola"
	}
	identity := &azmodels.Identity{
		IdentityID: uuid.New().String(),
		IdentitySourceID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Kind: "user",
		Name: name,
	}
	sql := "UPDATE \"identities\" .+"
	identityKind, _ := convertIdentityKindToID(identity.Kind)
	sqlRows := sqlmock.NewRows([]string{"identity_id", "identity_source_id", "account_id", "created_at", "updated_at", "kind", "name"}).
		AddRow(identity.IdentityID, identity.IdentitySourceID, identity.AccountID, identity.CreatedAt, identity.UpdatedAt, identityKind, identity.Name)
	sqlResult := sqlmock.NewResult(identity.AccountID, 1)
	return identity, sql, sqlRows, sqlResult
}

// registerIdentityForDeleteMocking register an identity for delete mocking.
func registerIdentityForDeleteMocking(account *azmodels.Account, name string) (*azmodels.Identity, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "nicola"
	}
	identity := &azmodels.Identity{
		IdentityID: uuid.New().String(),
		IdentitySourceID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Kind: "user",
		Name: name,
	}
	sql := "DELETE FROM \"identities\" WHERE .+"
	identityKind, _ := convertIdentityKindToID(identity.Kind)
	sqlRows := sqlmock.NewRows([]string{"identity_id", "identity_source_id", "account_id", "created_at", "updated_at", "kind", "name"}).
		AddRow(identity.IdentityID, identity.IdentitySourceID, identity.AccountID, identity.CreatedAt, identity.UpdatedAt, identityKind, identity.Name)
	sqlResult := sqlmock.NewResult(identity.AccountID, 1)
	return identity, sql, sqlRows, sqlResult
}

// registerIdentityForGetAllMocking registers the mocking for the GetAll method of the IdentityRepository
func registerIdentityForGetAllMocking() ([]azmodels.Identity, string, *sqlmock.Rows) {
	identities := []azmodels.Identity {
		{
			IdentityID: uuid.New().String(),
			IdentitySourceID: uuid.New().String(),
			AccountID: 581616507495,
			Name: "nicola",
			Kind: "user",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			IdentityID: uuid.New().String(),
			IdentitySourceID: uuid.New().String(),
			AccountID: 673389447445,
			Name: "mario",
			Kind: "user",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	sql := "SELECT .+ FROM \"identities\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"identity_id", "identity_source_id", "created_at", "updated_at", "account_id", "kind", "name"})
	for _, identity := range identities {
		identityKind, _ := convertIdentityKindToID(identity.Kind)
		sqlRows  = sqlRows.AddRow(identity.IdentityID, identity.IdentitySourceID, identity.CreatedAt, identity.UpdatedAt, identity.AccountID, identityKind, identity.Name)
	}
	return identities, sql, sqlRows
}


// registerTenantForInsertMocking registers an tenant for insert mocking.
func registerTenantForInsertMocking(account *azmodels.Account, name string) (*azmodels.Tenant, string, *sqlmock.Rows) {
	if name == "" {
		name = "authx"
	}
	tenant := &azmodels.Tenant{
		TenantID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "INSERT INTO \"tenants\" (.+) VALUES (.+)"
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "created_at", "updated_at", "account_id", "name"}).
		AddRow(tenant.TenantID, tenant.CreatedAt, tenant.UpdatedAt, tenant.AccountID, tenant.Name)
	return tenant, sql, sqlRows
}

// registerTenantForUpdateMocking register an tenant for update mocking.
func registerTenantForUpdateMocking(account *azmodels.Account, name string) (*azmodels.Tenant, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "authx"
	}
	tenant := &azmodels.Tenant{
		TenantID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "UPDATE \"tenants\" .+"
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "account_id", "created_at", "updated_at", "name"}).
		AddRow(tenant.TenantID, tenant.AccountID, tenant.CreatedAt, tenant.UpdatedAt, tenant.Name)
	sqlResult := sqlmock.NewResult(tenant.AccountID, 1)
	return tenant, sql, sqlRows, sqlResult
}

// registerTenantForDeleteMocking register an tenant for delete mocking.
func registerTenantForDeleteMocking(account *azmodels.Account, name string) (*azmodels.Tenant, string, *sqlmock.Rows, driver.Result) {
	if name == "" {
		name = "authx"
	}
	tenant := &azmodels.Tenant{
		TenantID: uuid.New().String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		AccountID: account.AccountID,
		Name: name,
	}
	sql := "DELETE FROM \"tenants\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "account_id", "created_at", "updated_at", "name"}).
		AddRow(tenant.TenantID, tenant.AccountID, tenant.CreatedAt, tenant.UpdatedAt, tenant.Name)
	sqlResult := sqlmock.NewResult(tenant.AccountID, 1)
	return tenant, sql, sqlRows, sqlResult
}

// registerTenantForGetAllMocking registers the mocking for the GetAll method of the TenantRepository
func registerTenantForGetAllMocking() ([]azmodels.Tenant, string, *sqlmock.Rows) {
	tenants := []azmodels.Tenant {
		{
			TenantID: "1609037a-0c69-4568-ba2a-792f90fc000f",
			AccountID: 581616507495,
			Name: "authx1",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			TenantID: "24f378b2-f12f-4a45-90a2-81bfa7e98229",
			AccountID: 673389447445,
			Name: "authx2",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	sql := "SELECT .+ FROM \"tenants\" WHERE .+"
	sqlRows := sqlmock.NewRows([]string{"tenant_id", "created_at", "updated_at", "account_id", "name"})
	for _, tenant := range tenants {
		sqlRows  = sqlRows.AddRow(tenant.TenantID, tenant.CreatedAt, tenant.UpdatedAt, tenant.AccountID, tenant.Name)
	}
	return tenants, sql, sqlRows
}

// TestNewPostgresAAPCentralStorage tests the newPostgresAAPCentralStorage function.
func TestNewPostgresAAPCentralStorage(t *testing.T) {
	assert := assert.New(t)

	runtimeCtx := azrtmmocks.NewRuntimeContextMock()
	storageCtx, err := azstorage.NewStorageContext(runtimeCtx, azstorage.StoragePostgres)
	if err != nil {
		t.Fatal(err)
	}
	pgConn, _, _, _ := newPostgresConnectionMock(t)

	storage, err := newPostgresAAPCentralStorage(nil, nil)
	azerrors.IsSystemError(err)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrInvalidInputParameter, err), "error should be ErrInvalidInputParameter")

	storage, err = newPostgresAAPCentralStorage(storageCtx, nil)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrInvalidInputParameter, err), "error should be ErrInvalidInputParameter")

	storage, err = newPostgresAAPCentralStorage(nil, pgConn)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrInvalidInputParameter, err), "error should be ErrInvalidInputParameter")

	storage, err = newPostgresAAPCentralStorage(storageCtx, pgConn)
	assert.NotNil(storage, "storage should not be nil")
	assert.Nil(err, "error should be nil")
}
