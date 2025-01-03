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

	azmodelaap "github.com/permguard/permguard/pkg/transport/models/aap"
)

// GrpcAAPClientMock is a mock type for the CliDependencies type.
type GrpcAAPClientMock struct {
	mock.Mock
}

// CreateApplication creates a new application.
func (m *GrpcAAPClientMock) CreateApplication(name string) (*azmodelaap.Application, error) {
	args := m.Called(name)
	var r0 *azmodelaap.Application
	if val, ok := args.Get(0).(*azmodelaap.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateApplication updates an application.
func (m *GrpcAAPClientMock) UpdateApplication(application *azmodelaap.Application) (*azmodelaap.Application, error) {
	args := m.Called(application)
	var r0 *azmodelaap.Application
	if val, ok := args.Get(0).(*azmodelaap.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteApplication deletes an application.
func (m *GrpcAAPClientMock) DeleteApplication(applicationID int64) (*azmodelaap.Application, error) {
	args := m.Called(applicationID)
	var r0 *azmodelaap.Application
	if val, ok := args.Get(0).(*azmodelaap.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchApplications fetches applications.
func (m *GrpcAAPClientMock) FetchApplications(page int32, pageSize int32) ([]azmodelaap.Application, error) {
	args := m.Called(page)
	var r0 []azmodelaap.Application
	if val, ok := args.Get(0).([]azmodelaap.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchApplicationsByID fetches applications by ID.
func (m *GrpcAAPClientMock) FetchApplicationsByID(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Application, error) {
	args := m.Called(page, pageSize, applicationID)
	var r0 []azmodelaap.Application
	if val, ok := args.Get(0).([]azmodelaap.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchApplicationsByName fetches applications by name.
func (m *GrpcAAPClientMock) FetchApplicationsByName(page int32, pageSize int32, name string) ([]azmodelaap.Application, error) {
	args := m.Called(page, pageSize, name)
	var r0 []azmodelaap.Application
	if val, ok := args.Get(0).([]azmodelaap.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchApplicationsBy fetches applications by.
func (m *GrpcAAPClientMock) FetchApplicationsBy(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Application, error) {
	args := m.Called(page, pageSize, applicationID, name)
	var r0 []azmodelaap.Application
	if val, ok := args.Get(0).([]azmodelaap.Application); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateIdentity creates a new identity.
func (m *GrpcAAPClientMock) CreateIdentity(applicationID int64, identitySourceID string, kind string, name string) (*azmodelaap.Identity, error) {
	args := m.Called(applicationID, identitySourceID, kind, name)
	var r0 *azmodelaap.Identity
	if val, ok := args.Get(0).(*azmodelaap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateIdentity updates an identity.
func (m *GrpcAAPClientMock) UpdateIdentity(identity *azmodelaap.Identity) (*azmodelaap.Identity, error) {
	args := m.Called(identity)
	var r0 *azmodelaap.Identity
	if val, ok := args.Get(0).(*azmodelaap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentity deletes an identity.
func (m *GrpcAAPClientMock) DeleteIdentity(applicationID int64, identityID string) (*azmodelaap.Identity, error) {
	args := m.Called(applicationID, identityID)
	var r0 *azmodelaap.Identity
	if val, ok := args.Get(0).(*azmodelaap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentities returns all identities.
func (m *GrpcAAPClientMock) FetchIdentities(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Identity, error) {
	args := m.Called(page, pageSize, applicationID)
	var r0 []azmodelaap.Identity
	if val, ok := args.Get(0).([]azmodelaap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitiesByID returns all identities filtering by identity id.
func (m *GrpcAAPClientMock) FetchIdentitiesByID(page int32, pageSize int32, applicationID int64, identityID string) ([]azmodelaap.Identity, error) {
	args := m.Called(page, pageSize, applicationID, identityID)
	var r0 []azmodelaap.Identity
	if val, ok := args.Get(0).([]azmodelaap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitiesByEmail returns all identities filtering by name.
func (m *GrpcAAPClientMock) FetchIdentitiesByEmail(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Identity, error) {
	args := m.Called(page, pageSize, applicationID, name)
	var r0 []azmodelaap.Identity
	if val, ok := args.Get(0).([]azmodelaap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitiesBy returns all identities filtering by all criteria.
func (m *GrpcAAPClientMock) FetchIdentitiesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodelaap.Identity, error) {
	args := m.Called(page, pageSize, applicationID, identitySourceID, identityID, kind, name)
	var r0 []azmodelaap.Identity
	if val, ok := args.Get(0).([]azmodelaap.Identity); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateIdentitySource creates a new identity source.
func (m *GrpcAAPClientMock) CreateIdentitySource(applicationID int64, name string) (*azmodelaap.IdentitySource, error) {
	args := m.Called(applicationID, name)
	var r0 *azmodelaap.IdentitySource
	if val, ok := args.Get(0).(*azmodelaap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateIdentitySource updates an identity source.
func (m *GrpcAAPClientMock) UpdateIdentitySource(identitySource *azmodelaap.IdentitySource) (*azmodelaap.IdentitySource, error) {
	args := m.Called(identitySource)
	var r0 *azmodelaap.IdentitySource
	if val, ok := args.Get(0).(*azmodelaap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteIdentitySource deletes an identity source.
func (m *GrpcAAPClientMock) DeleteIdentitySource(applicationID int64, identitySourceID string) (*azmodelaap.IdentitySource, error) {
	args := m.Called(applicationID, identitySourceID)
	var r0 *azmodelaap.IdentitySource
	if val, ok := args.Get(0).(*azmodelaap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySources returns all identity sources.
func (m *GrpcAAPClientMock) FetchIdentitySources(page int32, pageSize int32, applicationID int64) ([]azmodelaap.IdentitySource, error) {
	args := m.Called(page, pageSize, applicationID)
	var r0 []azmodelaap.IdentitySource
	if val, ok := args.Get(0).([]azmodelaap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
func (m *GrpcAAPClientMock) FetchIdentitySourcesByID(page int32, pageSize int32, applicationID int64, identitySourceID string) ([]azmodelaap.IdentitySource, error) {
	args := m.Called(page, pageSize, applicationID, identitySourceID)
	var r0 []azmodelaap.IdentitySource
	if val, ok := args.Get(0).([]azmodelaap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySourcesByName returns all identity sources filtering by name.
func (m *GrpcAAPClientMock) FetchIdentitySourcesByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.IdentitySource, error) {
	args := m.Called(page, pageSize, applicationID, name)
	var r0 []azmodelaap.IdentitySource
	if val, ok := args.Get(0).([]azmodelaap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
func (m *GrpcAAPClientMock) FetchIdentitySourcesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, name string) ([]azmodelaap.IdentitySource, error) {
	args := m.Called(page, pageSize, applicationID, identitySourceID, name)
	var r0 []azmodelaap.IdentitySource
	if val, ok := args.Get(0).([]azmodelaap.IdentitySource); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateTenant creates a tenant.
func (m *GrpcAAPClientMock) CreateTenant(applicationID int64, name string) (*azmodelaap.Tenant, error) {
	args := m.Called(applicationID, name)
	var r0 *azmodelaap.Tenant
	if val, ok := args.Get(0).(*azmodelaap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateTenant updates a tenant.
func (m *GrpcAAPClientMock) UpdateTenant(tenant *azmodelaap.Tenant) (*azmodelaap.Tenant, error) {
	args := m.Called(tenant)
	var r0 *azmodelaap.Tenant
	if val, ok := args.Get(0).(*azmodelaap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteTenant deletes a tenant.
func (m *GrpcAAPClientMock) DeleteTenant(applicationID int64, tenantID string) (*azmodelaap.Tenant, error) {
	args := m.Called(applicationID, tenantID)
	var r0 *azmodelaap.Tenant
	if val, ok := args.Get(0).(*azmodelaap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenants returns all tenants.
func (m *GrpcAAPClientMock) FetchTenants(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Tenant, error) {
	args := m.Called(page, pageSize, applicationID)
	var r0 []azmodelaap.Tenant
	if val, ok := args.Get(0).([]azmodelaap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenantsByID returns all tenants filtering by tenant id.
func (m *GrpcAAPClientMock) FetchTenantsByID(page int32, pageSize int32, applicationID int64, tenantID string) ([]azmodelaap.Tenant, error) {
	args := m.Called(page, pageSize, applicationID, tenantID)
	var r0 []azmodelaap.Tenant
	if val, ok := args.Get(0).([]azmodelaap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenantsByName returns all tenants filtering by name.
func (m *GrpcAAPClientMock) FetchTenantsByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Tenant, error) {
	args := m.Called(page, pageSize, applicationID, name)
	var r0 []azmodelaap.Tenant
	if val, ok := args.Get(0).([]azmodelaap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchTenantsBy returns all tenants filtering by tenant id and name.
func (m *GrpcAAPClientMock) FetchTenantsBy(page int32, pageSize int32, applicationID int64, tenantID string, name string) ([]azmodelaap.Tenant, error) {
	args := m.Called(page, pageSize, applicationID, tenantID, name)
	var r0 []azmodelaap.Tenant
	if val, ok := args.Get(0).([]azmodelaap.Tenant); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewGrpcAAPClientMock creates a new GrpcAAPClientMock.
func NewGrpcAAPClientMock() *GrpcAAPClientMock {
	return &GrpcAAPClientMock{}
}
