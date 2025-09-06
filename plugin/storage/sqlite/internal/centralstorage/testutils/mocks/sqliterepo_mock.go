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

// KeyValue retrieves a key-value pair by key.
func (m *MockSqliteRepo) KeyValue(db *sqlx.DB, zoneID int64, key string) (*repos.KeyValue, error) {
	args := m.Called(db, zoneID, key)
	var r0 *repos.KeyValue
	if val, ok := args.Get(0).(*repos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}
