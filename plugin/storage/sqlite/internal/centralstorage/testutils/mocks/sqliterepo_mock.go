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

	azifacade "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/facade"
)

// MockSqliteRepo sqlite ledger mock
type MockSqliteRepo struct {
	mock.Mock
}

// NewMockSqliteRepo create a new mock of SqliteRepo
func NewMockSqliteRepo() *MockSqliteRepo {
	return &MockSqliteRepo{}
}

// UpsertApplication creates or updates an application.
func (m *MockSqliteRepo) UpsertApplication(tx *sql.Tx, isCreate bool, application *azifacade.Application) (*azifacade.Application, error) {
	args := m.Called(tx, isCreate, application)
	var r0 *azifacade.Application
	if val, ok := args.Get(0).(*azifacade.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteApplication deletes an application.
func (m *MockSqliteRepo) DeleteApplication(tx *sql.Tx, applicationID int64) (*azifacade.Application, error) {
	args := m.Called(tx, applicationID)
	var r0 *azifacade.Application
	if val, ok := args.Get(0).(*azifacade.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchApplications fetches applications.
func (m *MockSqliteRepo) FetchApplications(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azifacade.Application, error) {
	args := m.Called(db, page, pageSize, filterID, filterName)
	var r0 []azifacade.Application
	if val, ok := args.Get(0).([]azifacade.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertIdentitySource creates or updates an identity source.
func (m *MockSqliteRepo) UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *azifacade.IdentitySource) (*azifacade.IdentitySource, error) {
	args := m.Called(tx, isCreate, identitySource)
	var r0 *azifacade.IdentitySource
	if val, ok := args.Get(0).(*azifacade.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentitySource deletes an identity source.
func (m *MockSqliteRepo) DeleteIdentitySource(tx *sql.Tx, applicationID int64, identitySourceID string) (*azifacade.IdentitySource, error) {
	args := m.Called(tx, applicationID, identitySourceID)
	var r0 *azifacade.IdentitySource
	if val, ok := args.Get(0).(*azifacade.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySources fetches identity sources.
func (m *MockSqliteRepo) FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azifacade.IdentitySource, error) {
	args := m.Called(db, page, pageSize, applicationID, filterID, filterName)
	var r0 []azifacade.IdentitySource
	if val, ok := args.Get(0).([]azifacade.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertIdentity creates or updates an identity.
func (m *MockSqliteRepo) UpsertIdentity(tx *sql.Tx, isCreate bool, identity *azifacade.Identity) (*azifacade.Identity, error) {
	args := m.Called(tx, isCreate, identity)
	var r0 *azifacade.Identity
	if val, ok := args.Get(0).(*azifacade.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentity deletes an identity.
func (m *MockSqliteRepo) DeleteIdentity(tx *sql.Tx, applicationID int64, identityID string) (*azifacade.Identity, error) {
	args := m.Called(tx, applicationID, identityID)
	var r0 *azifacade.Identity
	if val, ok := args.Get(0).(*azifacade.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentities fetches identities.
func (m *MockSqliteRepo) FetchIdentities(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azifacade.Identity, error) {
	args := m.Called(db, page, pageSize, applicationID, filterID, filterName)
	var r0 []azifacade.Identity
	if val, ok := args.Get(0).([]azifacade.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertTenant creates or updates an tenant.
func (m *MockSqliteRepo) UpsertTenant(tx *sql.Tx, isCreate bool, tenant *azifacade.Tenant) (*azifacade.Tenant, error) {
	args := m.Called(tx, isCreate, tenant)
	var r0 *azifacade.Tenant
	if val, ok := args.Get(0).(*azifacade.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteTenant deletes an tenant.
func (m *MockSqliteRepo) DeleteTenant(tx *sql.Tx, applicationID int64, tenantID string) (*azifacade.Tenant, error) {
	args := m.Called(tx, applicationID, tenantID)
	var r0 *azifacade.Tenant
	if val, ok := args.Get(0).(*azifacade.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenants fetches tenants.
func (m *MockSqliteRepo) FetchTenants(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azifacade.Tenant, error) {
	args := m.Called(db, page, pageSize, applicationID, filterID, filterName)
	var r0 []azifacade.Tenant
	if val, ok := args.Get(0).([]azifacade.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertLedger creates or updates a ledger.
func (m *MockSqliteRepo) UpsertLedger(tx *sql.Tx, isCreate bool, ledger *azifacade.Ledger) (*azifacade.Ledger, error) {
	args := m.Called(tx, isCreate, ledger)
	var r0 *azifacade.Ledger
	if val, ok := args.Get(0).(*azifacade.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertLedger creates or updates a ledger.
func (m *MockSqliteRepo) UpdateLedgerRef(tx *sql.Tx, applicationID int64, ledgerID, currentRef, newRef string) error {
	args := m.Called(tx, applicationID, ledgerID, currentRef, newRef)
	return args.Error(1)
}

// DeleteLedger deletes a ledger.
func (m *MockSqliteRepo) DeleteLedger(tx *sql.Tx, applicationID int64, ledgerID string) (*azifacade.Ledger, error) {
	args := m.Called(tx, applicationID, ledgerID)
	var r0 *azifacade.Ledger
	if val, ok := args.Get(0).(*azifacade.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgers fetches ledgers.
func (m *MockSqliteRepo) FetchLedgers(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]azifacade.Ledger, error) {
	args := m.Called(db, page, pageSize, applicationID, filterID, filterName)
	var r0 []azifacade.Ledger
	if val, ok := args.Get(0).([]azifacade.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertKeyValue creates or updates a key-value pair.
func (m *MockSqliteRepo) UpsertKeyValue(tx *sql.Tx, keyValue *azifacade.KeyValue) (*azifacade.KeyValue, error) {
	args := m.Called(tx, keyValue)
	var r0 *azifacade.KeyValue
	if val, ok := args.Get(0).(*azifacade.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// GetKeyValue retrieves a key-value pair by key.
func (m *MockSqliteRepo) GetKeyValue(db *sqlx.DB, key string) (*azifacade.KeyValue, error) {
	args := m.Called(db, key)
	var r0 *azifacade.KeyValue
	if val, ok := args.Get(0).(*azifacade.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}
