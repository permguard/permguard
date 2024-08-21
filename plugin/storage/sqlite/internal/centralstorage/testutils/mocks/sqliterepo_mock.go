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

	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// MockSqliteRepo sqlite repo mock
type MockSqliteRepo struct {
	mock.Mock
}

// NewMockSqliteRepo create a new mock of SqliteRepo
func NewMockSqliteRepo() *MockSqliteRepo{
	return &MockSqliteRepo{
	}
}

// UpsertAccount creates or updates an account.
func (m *MockSqliteRepo) UpsertAccount(tx *sql.Tx, isCreate bool, account *azrepos.Account) (*azrepos.Account, error) {
	args := m.Called(tx, isCreate, account)
	var r0 *azrepos.Account
	if val, ok := args.Get(0).(*azrepos.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteAccount deletes an account.
func (m *MockSqliteRepo) DeleteAccount(tx *sql.Tx, accountID int64) (*azrepos.Account, error) {
	args := m.Called(tx, accountID)
	var r0 *azrepos.Account
	if val, ok := args.Get(0).(*azrepos.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchAccounts fetches accounts.
func (m *MockSqliteRepo) FetchAccounts(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]azrepos.Account, error) {
	args := m.Called(db, page, pageSize, filterID, filterName)
	var r0 []azrepos.Account
	if val, ok := args.Get(0).([]azrepos.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}
