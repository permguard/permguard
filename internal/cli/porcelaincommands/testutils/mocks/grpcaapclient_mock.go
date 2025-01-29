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
	mock "github.com/stretchr/testify/mock"

	azmodelzap "github.com/permguard/permguard/pkg/transport/models/zap"
)

// GrpcZAPClientMock is a mock type for the CliDependencies type.
type GrpcZAPClientMock struct {
	mock.Mock
}

// CreateZone creates a new zone.
func (m *GrpcZAPClientMock) CreateZone(name string) (*azmodelzap.Zone, error) {
	args := m.Called(name)
	var r0 *azmodelzap.Zone
	if val, ok := args.Get(0).(*azmodelzap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateZone updates a zone.
func (m *GrpcZAPClientMock) UpdateZone(zone *azmodelzap.Zone) (*azmodelzap.Zone, error) {
	args := m.Called(zone)
	var r0 *azmodelzap.Zone
	if val, ok := args.Get(0).(*azmodelzap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteZone deletes a zone.
func (m *GrpcZAPClientMock) DeleteZone(zoneID int64) (*azmodelzap.Zone, error) {
	args := m.Called(zoneID)
	var r0 *azmodelzap.Zone
	if val, ok := args.Get(0).(*azmodelzap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZones fetches zones.
func (m *GrpcZAPClientMock) FetchZones(page int32, pageSize int32) ([]azmodelzap.Zone, error) {
	args := m.Called(page)
	var r0 []azmodelzap.Zone
	if val, ok := args.Get(0).([]azmodelzap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZonesByID fetches zones by ID.
func (m *GrpcZAPClientMock) FetchZonesByID(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Zone, error) {
	args := m.Called(page, pageSize, zoneID)
	var r0 []azmodelzap.Zone
	if val, ok := args.Get(0).([]azmodelzap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZonesByName fetches zones by name.
func (m *GrpcZAPClientMock) FetchZonesByName(page int32, pageSize int32, name string) ([]azmodelzap.Zone, error) {
	args := m.Called(page, pageSize, name)
	var r0 []azmodelzap.Zone
	if val, ok := args.Get(0).([]azmodelzap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchZonesBy fetches zones by.
func (m *GrpcZAPClientMock) FetchZonesBy(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Zone, error) {
	args := m.Called(page, pageSize, zoneID, name)
	var r0 []azmodelzap.Zone
	if val, ok := args.Get(0).([]azmodelzap.Zone); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateIdentity creates a new identity.
func (m *GrpcZAPClientMock) CreateIdentity(zoneID int64, identitySourceID string, kind string, name string) (*azmodelzap.Identity, error) {
	args := m.Called(zoneID, identitySourceID, kind, name)
	var r0 *azmodelzap.Identity
	if val, ok := args.Get(0).(*azmodelzap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateIdentity updates an identity.
func (m *GrpcZAPClientMock) UpdateIdentity(identity *azmodelzap.Identity) (*azmodelzap.Identity, error) {
	args := m.Called(identity)
	var r0 *azmodelzap.Identity
	if val, ok := args.Get(0).(*azmodelzap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentity deletes an identity.
func (m *GrpcZAPClientMock) DeleteIdentity(zoneID int64, identityID string) (*azmodelzap.Identity, error) {
	args := m.Called(zoneID, identityID)
	var r0 *azmodelzap.Identity
	if val, ok := args.Get(0).(*azmodelzap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentities returns all identities.
func (m *GrpcZAPClientMock) FetchIdentities(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Identity, error) {
	args := m.Called(page, pageSize, zoneID)
	var r0 []azmodelzap.Identity
	if val, ok := args.Get(0).([]azmodelzap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitiesByID returns all identities filtering by identity id.
func (m *GrpcZAPClientMock) FetchIdentitiesByID(page int32, pageSize int32, zoneID int64, identityID string) ([]azmodelzap.Identity, error) {
	args := m.Called(page, pageSize, zoneID, identityID)
	var r0 []azmodelzap.Identity
	if val, ok := args.Get(0).([]azmodelzap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitiesByEmail returns all identities filtering by name.
func (m *GrpcZAPClientMock) FetchIdentitiesByEmail(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Identity, error) {
	args := m.Called(page, pageSize, zoneID, name)
	var r0 []azmodelzap.Identity
	if val, ok := args.Get(0).([]azmodelzap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitiesBy returns all identities filtering by all criteria.
func (m *GrpcZAPClientMock) FetchIdentitiesBy(page int32, pageSize int32, zoneID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodelzap.Identity, error) {
	args := m.Called(page, pageSize, zoneID, identitySourceID, identityID, kind, name)
	var r0 []azmodelzap.Identity
	if val, ok := args.Get(0).([]azmodelzap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateIdentitySource creates a new identity source.
func (m *GrpcZAPClientMock) CreateIdentitySource(zoneID int64, name string) (*azmodelzap.IdentitySource, error) {
	args := m.Called(zoneID, name)
	var r0 *azmodelzap.IdentitySource
	if val, ok := args.Get(0).(*azmodelzap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateIdentitySource updates an identity source.
func (m *GrpcZAPClientMock) UpdateIdentitySource(identitySource *azmodelzap.IdentitySource) (*azmodelzap.IdentitySource, error) {
	args := m.Called(identitySource)
	var r0 *azmodelzap.IdentitySource
	if val, ok := args.Get(0).(*azmodelzap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentitySource deletes an identity source.
func (m *GrpcZAPClientMock) DeleteIdentitySource(zoneID int64, identitySourceID string) (*azmodelzap.IdentitySource, error) {
	args := m.Called(zoneID, identitySourceID)
	var r0 *azmodelzap.IdentitySource
	if val, ok := args.Get(0).(*azmodelzap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySources returns all identity sources.
func (m *GrpcZAPClientMock) FetchIdentitySources(page int32, pageSize int32, zoneID int64) ([]azmodelzap.IdentitySource, error) {
	args := m.Called(page, pageSize, zoneID)
	var r0 []azmodelzap.IdentitySource
	if val, ok := args.Get(0).([]azmodelzap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
func (m *GrpcZAPClientMock) FetchIdentitySourcesByID(page int32, pageSize int32, zoneID int64, identitySourceID string) ([]azmodelzap.IdentitySource, error) {
	args := m.Called(page, pageSize, zoneID, identitySourceID)
	var r0 []azmodelzap.IdentitySource
	if val, ok := args.Get(0).([]azmodelzap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySourcesByName returns all identity sources filtering by name.
func (m *GrpcZAPClientMock) FetchIdentitySourcesByName(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.IdentitySource, error) {
	args := m.Called(page, pageSize, zoneID, name)
	var r0 []azmodelzap.IdentitySource
	if val, ok := args.Get(0).([]azmodelzap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
func (m *GrpcZAPClientMock) FetchIdentitySourcesBy(page int32, pageSize int32, zoneID int64, identitySourceID string, name string) ([]azmodelzap.IdentitySource, error) {
	args := m.Called(page, pageSize, zoneID, identitySourceID, name)
	var r0 []azmodelzap.IdentitySource
	if val, ok := args.Get(0).([]azmodelzap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateTenant creates a tenant.
func (m *GrpcZAPClientMock) CreateTenant(zoneID int64, name string) (*azmodelzap.Tenant, error) {
	args := m.Called(zoneID, name)
	var r0 *azmodelzap.Tenant
	if val, ok := args.Get(0).(*azmodelzap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateTenant updates a tenant.
func (m *GrpcZAPClientMock) UpdateTenant(tenant *azmodelzap.Tenant) (*azmodelzap.Tenant, error) {
	args := m.Called(tenant)
	var r0 *azmodelzap.Tenant
	if val, ok := args.Get(0).(*azmodelzap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteTenant deletes a tenant.
func (m *GrpcZAPClientMock) DeleteTenant(zoneID int64, tenantID string) (*azmodelzap.Tenant, error) {
	args := m.Called(zoneID, tenantID)
	var r0 *azmodelzap.Tenant
	if val, ok := args.Get(0).(*azmodelzap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenants returns all tenants.
func (m *GrpcZAPClientMock) FetchTenants(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Tenant, error) {
	args := m.Called(page, pageSize, zoneID)
	var r0 []azmodelzap.Tenant
	if val, ok := args.Get(0).([]azmodelzap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenantsByID returns all tenants filtering by tenant id.
func (m *GrpcZAPClientMock) FetchTenantsByID(page int32, pageSize int32, zoneID int64, tenantID string) ([]azmodelzap.Tenant, error) {
	args := m.Called(page, pageSize, zoneID, tenantID)
	var r0 []azmodelzap.Tenant
	if val, ok := args.Get(0).([]azmodelzap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenantsByName returns all tenants filtering by name.
func (m *GrpcZAPClientMock) FetchTenantsByName(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Tenant, error) {
	args := m.Called(page, pageSize, zoneID, name)
	var r0 []azmodelzap.Tenant
	if val, ok := args.Get(0).([]azmodelzap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenantsBy returns all tenants filtering by tenant id and name.
func (m *GrpcZAPClientMock) FetchTenantsBy(page int32, pageSize int32, zoneID int64, tenantID string, name string) ([]azmodelzap.Tenant, error) {
	args := m.Called(page, pageSize, zoneID, tenantID, name)
	var r0 []azmodelzap.Tenant
	if val, ok := args.Get(0).([]azmodelzap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewGrpcZAPClientMock creates a new GrpcZAPClientMock.
func NewGrpcZAPClientMock() *GrpcZAPClientMock {
	return &GrpcZAPClientMock{}
}
