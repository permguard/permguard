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

package mocks

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	mock "github.com/stretchr/testify/mock"

	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
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
func (m *MockSqliteRepo) UpsertZone(_ context.Context, tx *sql.Tx, isCreate bool, zone *azrepos.Zone) (*azrepos.Zone, error) {
	args := m.Called(tx, isCreate, zone)
	var r0 *azrepos.Zone
	if val, ok := args.Get(0).(*azrepos.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteZone deletes a zone.
func (m *MockSqliteRepo) DeleteZone(_ context.Context, tx *sql.Tx, zoneID int64) (*azrepos.Zone, error) {
	args := m.Called(tx, zoneID)
	var r0 *azrepos.Zone
	if val, ok := args.Get(0).(*azrepos.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZones fetches zones.
func (m *MockSqliteRepo) FetchZones(_ context.Context, db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azrepos.Zone, error) {
	args := m.Called(db, page, pageSize, filterID, filterName)
	var r0 []azrepos.Zone
	if val, ok := args.Get(0).([]azrepos.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertLedger creates or updates a ledger.
func (m *MockSqliteRepo) UpsertLedger(_ context.Context, tx *sql.Tx, isCreate bool, ledger *azrepos.Ledger) (*azrepos.Ledger, error) {
	args := m.Called(tx, isCreate, ledger)
	var r0 *azrepos.Ledger
	if val, ok := args.Get(0).(*azrepos.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateLedgerRef creates or updates a ledger.
func (m *MockSqliteRepo) UpdateLedgerRef(_ context.Context, tx *sql.Tx, zoneID int64, ledgerID, currentRef, newRef, txid string) error {
	args := m.Called(tx, zoneID, ledgerID, currentRef, newRef, txid)
	return args.Error(1)
}

// DeleteLedger deletes a ledger.
func (m *MockSqliteRepo) DeleteLedger(_ context.Context, tx *sql.Tx, zoneID int64, ledgerID string) (*azrepos.Ledger, error) {
	args := m.Called(tx, zoneID, ledgerID)
	var r0 *azrepos.Ledger
	if val, ok := args.Get(0).(*azrepos.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgers fetches ledgers.
func (m *MockSqliteRepo) FetchLedgers(_ context.Context, db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]azrepos.Ledger, error) {
	args := m.Called(db, page, pageSize, zoneID, filterID, filterName)
	var r0 []azrepos.Ledger
	if val, ok := args.Get(0).([]azrepos.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpsertKeyValue creates or updates a key-value pair.
func (m *MockSqliteRepo) UpsertKeyValue(_ context.Context, tx *sql.Tx, keyValue *azrepos.KeyValue, txid string) (*azrepos.KeyValue, error) {
	args := m.Called(tx, keyValue, txid)
	var r0 *azrepos.KeyValue
	if val, ok := args.Get(0).(*azrepos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// KeyValue retrieves a key-value pair by key.
func (m *MockSqliteRepo) KeyValue(_ context.Context, db *sqlx.DB, zoneID int64, key string) (*azrepos.KeyValue, error) {
	args := m.Called(db, zoneID, key)
	var r0 *azrepos.KeyValue
	if val, ok := args.Get(0).(*azrepos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// KeyValueTx retrieves a key-value pair by key within a transaction.
func (m *MockSqliteRepo) KeyValueTx(_ context.Context, tx *sql.Tx, zoneID int64, key string) (*azrepos.KeyValue, error) {
	args := m.Called(tx, zoneID, key)
	var r0 *azrepos.KeyValue
	if val, ok := args.Get(0).(*azrepos.KeyValue); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreatePushTransaction inserts a new push transaction.
func (m *MockSqliteRepo) CreatePushTransaction(_ context.Context, tx *sql.Tx, pushTx *azrepos.PushTransaction) error {
	args := m.Called(tx, pushTx)
	return args.Error(0)
}

// UpdatePushTransactionStatus updates the status of a push transaction.
func (m *MockSqliteRepo) UpdatePushTransactionStatus(_ context.Context, tx *sql.Tx, txid string, status string) error {
	args := m.Called(tx, txid, status)
	return args.Error(0)
}

// UpdatePushTransactionStatusNoTx updates the status without a transaction.
func (m *MockSqliteRepo) UpdatePushTransactionStatusNoTx(_ context.Context, db *sqlx.DB, txid string, status string) error {
	args := m.Called(db, txid, status)
	return args.Error(0)
}

// GetPushTransaction retrieves a push transaction by txid.
func (m *MockSqliteRepo) GetPushTransaction(_ context.Context, db *sqlx.DB, txid string) (*azrepos.PushTransaction, error) {
	args := m.Called(db, txid)
	var r0 *azrepos.PushTransaction
	if val, ok := args.Get(0).(*azrepos.PushTransaction); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchStalePushTransactions retrieves pending push transactions older than the given threshold.
func (m *MockSqliteRepo) FetchStalePushTransactions(_ context.Context, db *sqlx.DB, olderThan time.Time) ([]azrepos.PushTransaction, error) {
	args := m.Called(db, olderThan)
	var r0 []azrepos.PushTransaction
	if val, ok := args.Get(0).([]azrepos.PushTransaction); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteKeyValuesByTxID deletes all key-value pairs associated with the given txid and zone.
func (m *MockSqliteRepo) DeleteKeyValuesByTxID(_ context.Context, tx *sql.Tx, zoneID int64, txid string) (int64, error) {
	args := m.Called(tx, zoneID, txid)
	return args.Get(0).(int64), args.Error(1)
}
