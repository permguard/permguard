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

// Package mocks implements mocks for testing.
package mocks

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	mock "github.com/stretchr/testify/mock"

	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// MockSqliteRepo sqlite repo mock
type MockSqliteRepo struct {
	mock.Mock
}

// NewMockSqliteRepo create a new mock of SqliteRepo
func NewMockSqliteRepo() *MockSqliteRepo {
	return &MockSqliteRepo{}
}

// UpsertAccount creates or updates an account.
func (m *MockSqliteRepo) UpsertAccount(tx *sql.Tx, isCreate bool, account *azirepos.Account) (*azirepos.Account, error) {
	args := m.Called(tx, isCreate, account)
	var r0 *azirepos.Account
	if val, ok := args.Get(0).(*azirepos.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteAccount deletes an account.
func (m *MockSqliteRepo) DeleteAccount(tx *sql.Tx, accountID int64) (*azirepos.Account, error) {
	args := m.Called(tx, accountID)
	var r0 *azirepos.Account
	if val, ok := args.Get(0).(*azirepos.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchAccounts fetches accounts.
func (m *MockSqliteRepo) FetchAccounts(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azirepos.Account, error) {
	args := m.Called(db, page, pageSize, filterID, filterName)
	var r0 []azirepos.Account
	if val, ok := args.Get(0).([]azirepos.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertIdentitySource creates or updates an identity source.
func (m *MockSqliteRepo) UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *azirepos.IdentitySource) (*azirepos.IdentitySource, error) {
	args := m.Called(tx, isCreate, identitySource)
	var r0 *azirepos.IdentitySource
	if val, ok := args.Get(0).(*azirepos.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentitySource deletes an identity source.
func (m *MockSqliteRepo) DeleteIdentitySource(tx *sql.Tx, accountID int64, identitySourceID string) (*azirepos.IdentitySource, error) {
	args := m.Called(tx, accountID, identitySourceID)
	var r0 *azirepos.IdentitySource
	if val, ok := args.Get(0).(*azirepos.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySources fetches identity sources.
func (m *MockSqliteRepo) FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.IdentitySource, error) {
	args := m.Called(db, page, pageSize, accountID, filterID, filterName)
	var r0 []azirepos.IdentitySource
	if val, ok := args.Get(0).([]azirepos.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertIdentity creates or updates an identity.
func (m *MockSqliteRepo) UpsertIdentity(tx *sql.Tx, isCreate bool, identity *azirepos.Identity) (*azirepos.Identity, error) {
	args := m.Called(tx, isCreate, identity)
	var r0 *azirepos.Identity
	if val, ok := args.Get(0).(*azirepos.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentity deletes an identity.
func (m *MockSqliteRepo) DeleteIdentity(tx *sql.Tx, accountID int64, identityID string) (*azirepos.Identity, error) {
	args := m.Called(tx, accountID, identityID)
	var r0 *azirepos.Identity
	if val, ok := args.Get(0).(*azirepos.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentities fetches identities.
func (m *MockSqliteRepo) FetchIdentities(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.Identity, error) {
	args := m.Called(db, page, pageSize, accountID, filterID, filterName)
	var r0 []azirepos.Identity
	if val, ok := args.Get(0).([]azirepos.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertTenant creates or updates an tenant.
func (m *MockSqliteRepo) UpsertTenant(tx *sql.Tx, isCreate bool, tenant *azirepos.Tenant) (*azirepos.Tenant, error) {
	args := m.Called(tx, isCreate, tenant)
	var r0 *azirepos.Tenant
	if val, ok := args.Get(0).(*azirepos.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteTenant deletes an tenant.
func (m *MockSqliteRepo) DeleteTenant(tx *sql.Tx, accountID int64, tenantID string) (*azirepos.Tenant, error) {
	args := m.Called(tx, accountID, tenantID)
	var r0 *azirepos.Tenant
	if val, ok := args.Get(0).(*azirepos.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenants fetches tenants.
func (m *MockSqliteRepo) FetchTenants(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.Tenant, error) {
	args := m.Called(db, page, pageSize, accountID, filterID, filterName)
	var r0 []azirepos.Tenant
	if val, ok := args.Get(0).([]azirepos.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertRepository creates or updates a repository.
func (m *MockSqliteRepo) UpsertRepository(tx *sql.Tx, isCreate bool, repository *azirepos.Repository) (*azirepos.Repository, error) {
	args := m.Called(tx, isCreate, repository)
	var r0 *azirepos.Repository
	if val, ok := args.Get(0).(*azirepos.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertRepository creates or updates a repository.
func (m *MockSqliteRepo) UpdateRepositoryRefs(tx *sql.Tx, accountID int64, repositoryID, currentRef, newRef string) error {
	args := m.Called(tx, accountID, repositoryID, currentRef, newRef)
	return args.Error(1)
}

// DeleteRepository deletes a repository.
func (m *MockSqliteRepo) DeleteRepository(tx *sql.Tx, accountID int64, repositoryID string) (*azirepos.Repository, error) {
	args := m.Called(tx, accountID, repositoryID)
	var r0 *azirepos.Repository
	if val, ok := args.Get(0).(*azirepos.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchRepositories fetches repositories.
func (m *MockSqliteRepo) FetchRepositories(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]azirepos.Repository, error) {
	args := m.Called(db, page, pageSize, accountID, filterID, filterName)
	var r0 []azirepos.Repository
	if val, ok := args.Get(0).([]azirepos.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertKeyValue creates or updates a key-value pair.
func (m *MockSqliteRepo) UpsertKeyValue(tx *sql.Tx, keyValue *azirepos.KeyValue) (*azirepos.KeyValue, error) {
	args := m.Called(tx, keyValue)
	var r0 *azirepos.KeyValue
	if val, ok := args.Get(0).(*azirepos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// GetKeyValue retrieves a key-value pair by key.
func (m *MockSqliteRepo) GetKeyValue(db *sqlx.DB, key string) (*azirepos.KeyValue, error) {
	args := m.Called(db, key)
	var r0 *azirepos.KeyValue
	if val, ok := args.Get(0).(*azirepos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}
