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
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/permguard/permguard/pkg/agents/storage"
)

// MockSQLiteConnector sqlite connector mock
type MockSQLiteConnector struct {
	mock.Mock
}

// NewMockSQLiteConnector creates a new mock of SQLiteConnector.
func NewMockSQLiteConnector() *MockSQLiteConnector {
	return &MockSQLiteConnector{}
}

// GetStorage returns the storage kind.
func (m *MockSQLiteConnector) GetStorage() storage.StorageKind {
	args := m.Called()
	var r0 storage.StorageKind
	if val, ok := args.Get(0).(storage.StorageKind); ok {
		r0 = val
	}
	return r0
}

// Connect connects to the sqlite database.
func (m *MockSQLiteConnector) Connect(logger *zap.Logger, ctx *storage.StorageContext) (*sqlx.DB, error) {
	args := m.Called(logger, ctx)
	var r0 *sqlx.DB
	if val, ok := args.Get(0).(*sqlx.DB); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// Disconnect disconnects from the sqlite database.
func (m *MockSQLiteConnector) Disconnect(logger *zap.Logger, ctx *storage.StorageContext) error {
	args := m.Called(logger, ctx)
	return args.Error(0)
}
