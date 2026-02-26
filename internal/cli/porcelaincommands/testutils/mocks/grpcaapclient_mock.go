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
	mock "github.com/stretchr/testify/mock"

	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// GrpcZAPClientMock is a mock type for the CliDependencies type.
type GrpcZAPClientMock struct {
	mock.Mock
}

// CreateZone creates a new zone.
func (m *GrpcZAPClientMock) CreateZone(name string) (*zap.Zone, error) {
	args := m.Called(name)
	var r0 *zap.Zone
	if val, ok := args.Get(0).(*zap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateZone updates a zone.
func (m *GrpcZAPClientMock) UpdateZone(zone *zap.Zone) (*zap.Zone, error) {
	args := m.Called(zone)
	var r0 *zap.Zone
	if val, ok := args.Get(0).(*zap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteZone deletes a zone.
func (m *GrpcZAPClientMock) DeleteZone(zoneID int64) (*zap.Zone, error) {
	args := m.Called(zoneID)
	var r0 *zap.Zone
	if val, ok := args.Get(0).(*zap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZones fetches zones.
func (m *GrpcZAPClientMock) FetchZones(page int32, _ int32) ([]zap.Zone, error) {
	args := m.Called(page)
	var r0 []zap.Zone
	if val, ok := args.Get(0).([]zap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZonesByID fetches zones by ID.
func (m *GrpcZAPClientMock) FetchZonesByID(page int32, pageSize int32, zoneID int64) ([]zap.Zone, error) {
	args := m.Called(page, pageSize, zoneID)
	var r0 []zap.Zone
	if val, ok := args.Get(0).([]zap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZonesByName fetches zones by name.
func (m *GrpcZAPClientMock) FetchZonesByName(page int32, pageSize int32, name string) ([]zap.Zone, error) {
	args := m.Called(page, pageSize, name)
	var r0 []zap.Zone
	if val, ok := args.Get(0).([]zap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZonesBy fetches zones by.
func (m *GrpcZAPClientMock) FetchZonesBy(page int32, pageSize int32, zoneID int64, name string) ([]zap.Zone, error) {
	args := m.Called(page, pageSize, zoneID, name)
	var r0 []zap.Zone
	if val, ok := args.Get(0).([]zap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewGrpcZAPClientMock creates a new GrpcZAPClientMock.
func NewGrpcZAPClientMock() *GrpcZAPClientMock {
	return &GrpcZAPClientMock{}
}
