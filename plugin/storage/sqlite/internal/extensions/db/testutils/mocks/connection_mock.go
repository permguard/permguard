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
	"go.uber.org/zap"

	"github.com/jmoiron/sqlx"
	mock "github.com/stretchr/testify/mock"

	"github.com/permguard/permguard/pkg/agents/storage"
)

// SQLiteConnectionMock is a mock type for the SQLiteConnection type.
type SQLiteConnectionMock struct {
	mock.Mock
}

// Storage returns the storage kind.
func (c *SQLiteConnectionMock) Storage() storage.StorageKind {
	ret := c.Called()

	var r0 storage.StorageKind
	if rf, ok := ret.Get(0).(func() storage.StorageKind); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(storage.StorageKind)
	}
	return r0
}

// Connect connects to the storage.
func (c *SQLiteConnectionMock) Connect(logger *zap.Logger, ctx *storage.StorageContext) (*sqlx.DB, error) {
	ret := c.Called(logger, ctx)

	var r0 *sqlx.DB
	if rf, ok := ret.Get(0).(func(*zap.Logger, *storage.StorageContext) *sqlx.DB); ok {
		r0 = rf(logger, ctx)
	} else {
		r0 = ret.Get(0).(*sqlx.DB)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*zap.Logger, *storage.StorageContext) error); ok {
		r1 = rf(logger, ctx)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(error)
		}
	}
	return r0, r1
}

// Disconnect disconnects the connection.
func (c *SQLiteConnectionMock) Disconnect(logger *zap.Logger, ctx *storage.StorageContext) error {
	ret := c.Called(logger, ctx)

	var r0 error = nil
	if rf, ok := ret.Get(0).(func(*zap.Logger, *storage.StorageContext) error); ok {
		r0 = rf(logger, ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(error)
		}
	}
	return r0
}

// NewSQLiteConnectionMock creates a new SQLiteConnectionMock.
func NewSQLiteConnectionMock() *SQLiteConnectionMock {
	return &SQLiteConnectionMock{}
}
