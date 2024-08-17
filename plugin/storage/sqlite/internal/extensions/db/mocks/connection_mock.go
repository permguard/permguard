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
	"database/sql"

	"go.uber.org/zap"

	mock "github.com/stretchr/testify/mock"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// SQLiteConnectionMock is a mock type for the SQLiteConnection type.
type SQLiteConnectionMock struct {
	mock.Mock
}

// GetStorage returns the storage kind.
func (c *SQLiteConnectionMock) GetStorage() azstorage.StorageKind {
	ret := c.Called()

	var r0 azstorage.StorageKind
	if rf, ok := ret.Get(0).(func() azstorage.StorageKind); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(azstorage.StorageKind)
	}
	return r0
}

// Connect connects to the storage.
func (c *SQLiteConnectionMock) Connect(logger *zap.Logger, ctx *azstorage.StorageContext) (*sql.DB, error) {
	ret := c.Called(logger, ctx)

	var r0 *sql.DB
	if rf, ok := ret.Get(0).(func(*zap.Logger, *azstorage.StorageContext) *sql.DB); ok {
		r0 = rf(logger, ctx)
	} else {
		r0 = ret.Get(0).(*sql.DB)
	}

	var r1 error = nil
	if rf, ok := ret.Get(1).(func(*zap.Logger, *azstorage.StorageContext) error); ok {
		r1 = rf(logger, ctx)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(error)
		}
	}
	return r0, r1
}

// Disconnect disconnects the connection.
func (c *SQLiteConnectionMock) Disconnect(logger *zap.Logger, ctx *azstorage.StorageContext) error {
	ret := c.Called(logger, ctx)

	var r0 error = nil
	if rf, ok := ret.Get(0).(func(*zap.Logger, *azstorage.StorageContext) error); ok {
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
