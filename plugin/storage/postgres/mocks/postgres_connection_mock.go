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

	mock "github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"gorm.io/gorm"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// PostgresConnectionMock is a mock type for the PostgresConnection type.
type PostgresConnectionMock struct {
	mock.Mock
}

// GetStorage returns the storage kind.
func (c *PostgresConnectionMock) GetStorage() azstorage.StorageKind {
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
func (c *PostgresConnectionMock) Connect(logger *zap.Logger, ctx context.Context) (*gorm.DB, error) {
	ret := c.Called(logger, ctx)

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func(*zap.Logger, context.Context) *gorm.DB); ok {
		r0 = rf(logger, ctx)
	} else {
		r0 = ret.Get(0).(*gorm.DB)
	}

	var r1 error = nil
	if rf, ok := ret.Get(1).(func(*zap.Logger, context.Context) error); ok {
		r1 = rf(logger, ctx)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(error)
		}
	}
	return r0, r1
}

// Disconnect disconnects the connection.
func (c *PostgresConnectionMock) Disconnect(logger *zap.Logger, ctx context.Context) error {
	ret := c.Called(logger, ctx)

	var r0 error = nil
	if rf, ok := ret.Get(0).(func(*zap.Logger, context.Context) error); ok {
		r0 = rf(logger, ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(error)
		}
	}
	return r0
}

// NewPostgresConnectionMock creates a new PostgresConnectionMock.
func NewPostgresConnectionMock() *PostgresConnectionMock {
	return &PostgresConnectionMock{}
}
