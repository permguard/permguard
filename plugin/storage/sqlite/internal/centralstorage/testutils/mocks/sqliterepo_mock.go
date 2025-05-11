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

	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// MockSqliteRepo sqlite ledger mock
type MockSqliteRepo struct {
	mock.Mock
}

// NewMockSqliteRepo create a new mock of SqliteRepo
func NewMockSqliteRepo() *MockSqliteRepo {
	return &MockSqliteRepo{}
}

// UpsertZone creates or updates a zone.
func (m *MockSqliteRepo) UpsertZone(tx *sql.Tx, isCreate bool, zone *repos.Zone) (*repos.Zone, error) {
	args := m.Called(tx, isCreate, zone)
	var r0 *repos.Zone
	if val, ok := args.Get(0).(*repos.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteZone deletes a zone.
func (m *MockSqliteRepo) DeleteZone(tx *sql.Tx, zoneID int64) (*repos.Zone, error) {
	args := m.Called(tx, zoneID)
	var r0 *repos.Zone
	if val, ok := args.Get(0).(*repos.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZones fetches zones.
func (m *MockSqliteRepo) FetchZones(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]repos.Zone, error) {
	args := m.Called(db, page, pageSize, filterID, filterName)
	var r0 []repos.Zone
	if val, ok := args.Get(0).([]repos.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertIdentitySource creates or updates an identity source.
func (m *MockSqliteRepo) UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *repos.IdentitySource) (*repos.IdentitySource, error) {
	args := m.Called(tx, isCreate, identitySource)
	var r0 *repos.IdentitySource
	if val, ok := args.Get(0).(*repos.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentitySource deletes an identity source.
func (m *MockSqliteRepo) DeleteIdentitySource(tx *sql.Tx, zoneID int64, identitySourceID string) (*repos.IdentitySource, error) {
	args := m.Called(tx, zoneID, identitySourceID)
	var r0 *repos.IdentitySource
	if val, ok := args.Get(0).(*repos.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySources fetches identity sources.
func (m *MockSqliteRepo) FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.IdentitySource, error) {
	args := m.Called(db, page, pageSize, zoneID, filterID, filterName)
	var r0 []repos.IdentitySource
	if val, ok := args.Get(0).([]repos.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertIdentity creates or updates an identity.
func (m *MockSqliteRepo) UpsertIdentity(tx *sql.Tx, isCreate bool, identity *repos.Identity) (*repos.Identity, error) {
	args := m.Called(tx, isCreate, identity)
	var r0 *repos.Identity
	if val, ok := args.Get(0).(*repos.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentity deletes an identity.
func (m *MockSqliteRepo) DeleteIdentity(tx *sql.Tx, zoneID int64, identityID string) (*repos.Identity, error) {
	args := m.Called(tx, zoneID, identityID)
	var r0 *repos.Identity
	if val, ok := args.Get(0).(*repos.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentities fetches identities.
func (m *MockSqliteRepo) FetchIdentities(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.Identity, error) {
	args := m.Called(db, page, pageSize, zoneID, filterID, filterName)
	var r0 []repos.Identity
	if val, ok := args.Get(0).([]repos.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertTenant creates or updates an tenant.
func (m *MockSqliteRepo) UpsertTenant(tx *sql.Tx, isCreate bool, tenant *repos.Tenant) (*repos.Tenant, error) {
	args := m.Called(tx, isCreate, tenant)
	var r0 *repos.Tenant
	if val, ok := args.Get(0).(*repos.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteTenant deletes an tenant.
func (m *MockSqliteRepo) DeleteTenant(tx *sql.Tx, zoneID int64, tenantID string) (*repos.Tenant, error) {
	args := m.Called(tx, zoneID, tenantID)
	var r0 *repos.Tenant
	if val, ok := args.Get(0).(*repos.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenants fetches tenants.
func (m *MockSqliteRepo) FetchTenants(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.Tenant, error) {
	args := m.Called(db, page, pageSize, zoneID, filterID, filterName)
	var r0 []repos.Tenant
	if val, ok := args.Get(0).([]repos.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertLedger creates or updates a ledger.
func (m *MockSqliteRepo) UpsertLedger(tx *sql.Tx, isCreate bool, ledger *repos.Ledger) (*repos.Ledger, error) {
	args := m.Called(tx, isCreate, ledger)
	var r0 *repos.Ledger
	if val, ok := args.Get(0).(*repos.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateLedgerRef creates or updates a ledger.
func (m *MockSqliteRepo) UpdateLedgerRef(tx *sql.Tx, zoneID int64, ledgerID, currentRef, newRef string) error {
	args := m.Called(tx, zoneID, ledgerID, currentRef, newRef)
	return args.Error(1)
}

// DeleteLedger deletes a ledger.
func (m *MockSqliteRepo) DeleteLedger(tx *sql.Tx, zoneID int64, ledgerID string) (*repos.Ledger, error) {
	args := m.Called(tx, zoneID, ledgerID)
	var r0 *repos.Ledger
	if val, ok := args.Get(0).(*repos.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgers fetches ledgers.
func (m *MockSqliteRepo) FetchLedgers(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]repos.Ledger, error) {
	args := m.Called(db, page, pageSize, zoneID, filterID, filterName)
	var r0 []repos.Ledger
	if val, ok := args.Get(0).([]repos.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertKeyValue creates or updates a key-value pair.
func (m *MockSqliteRepo) UpsertKeyValue(tx *sql.Tx, keyValue *repos.KeyValue) (*repos.KeyValue, error) {
	args := m.Called(tx, keyValue)
	var r0 *repos.KeyValue
	if val, ok := args.Get(0).(*repos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// GetKeyValue retrieves a key-value pair by key.
func (m *MockSqliteRepo) GetKeyValue(db *sqlx.DB, zoneID int64, key string) (*repos.KeyValue, error) {
	args := m.Called(db, zoneID, key)
	var r0 *repos.KeyValue
	if val, ok := args.Get(0).(*repos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}
