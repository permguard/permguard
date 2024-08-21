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
	"github.com/stretchr/testify/mock"
	"github.com/jmoiron/sqlx"

	azidb "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/db"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// MockSqliteExecutor sqlite executor mock
type MockSqliteExecutor struct {
	mock.Mock
}

// NewMockSqliteExecutor create a new mock of SqliteExecutor
func NewMockSqliteExecutor() *MockSqliteExecutor{
	return &MockSqliteExecutor{
	}
}

// Connect connects to the sqlite database.
func (m *MockSqliteExecutor) Connect(ctx *azstorage.StorageContext, sqliteConnector azidb.SQLiteConnector) (*sqlx.DB, error) {
	args := m.Called(ctx, sqliteConnector)
	var r0 *sqlx.DB
	if val, ok := args.Get(0).(*sqlx.DB); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

