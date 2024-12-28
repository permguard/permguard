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

package clients

import (
	azmodels "github.com/permguard/permguard/pkg/transport/models"
)

// GrpcAAPClient is the gRPC AAP client servicer.
type GrpcAAPClient interface {
	// CreateApplication creates a new application.
	CreateApplication(name string) (*azmodels.Application, error)
	// UpdateApplication updates an application.
	UpdateApplication(application *azmodels.Application) (*azmodels.Application, error)
	// DeleteApplication deletes an application.
	DeleteApplication(applicationID int64) (*azmodels.Application, error)
	// FetchApplications fetches applications.
	FetchApplications(page int32, pageSize int32) ([]azmodels.Application, error)
	// FetchApplicationsByID fetches applications by ID.
	FetchApplicationsByID(page int32, pageSize int32, applicationID int64) ([]azmodels.Application, error)
	// FetchApplicationsByName fetches applications by name.
	FetchApplicationsByName(page int32, pageSize int32, name string) ([]azmodels.Application, error)
	// FetchApplicationsBy fetches applications by.
	FetchApplicationsBy(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.Application, error)
	// CreateIdentity creates a new identity.
	CreateIdentity(applicationID int64, identitySourceID string, kind string, name string) (*azmodels.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(applicationID int64, identityID string) (*azmodels.Identity, error)
	// FetchIdentities returns all identities.
	FetchIdentities(page int32, pageSize int32, applicationID int64) ([]azmodels.Identity, error)
	// FetchIdentitiesByID returns all identities filtering by identity id.
	FetchIdentitiesByID(page int32, pageSize int32, applicationID int64, identityID string) ([]azmodels.Identity, error)
	// FetchIdentitiesByEmail returns all identities filtering by name.
	FetchIdentitiesByEmail(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.Identity, error)
	// FetchIdentitiesBy returns all identities filtering by all criteria.
	FetchIdentitiesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodels.Identity, error)
	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(applicationID int64, name string) (*azmodels.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(applicationID int64, identitySourceID string) (*azmodels.IdentitySource, error)
	// FetchIdentitySources returns all identity sources.
	FetchIdentitySources(page int32, pageSize int32, applicationID int64) ([]azmodels.IdentitySource, error)
	// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
	FetchIdentitySourcesByID(page int32, pageSize int32, applicationID int64, identitySourceID string) ([]azmodels.IdentitySource, error)
	// FetchIdentitySourcesByName returns all identity sources filtering by name.
	FetchIdentitySourcesByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.IdentitySource, error)
	// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
	FetchIdentitySourcesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, name string) ([]azmodels.IdentitySource, error)
	// CreateTenant creates a tenant.
	CreateTenant(applicationID int64, name string) (*azmodels.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(applicationID int64, tenantID string) (*azmodels.Tenant, error)
	// FetchTenants returns all tenants.
	FetchTenants(page int32, pageSize int32, applicationID int64) ([]azmodels.Tenant, error)
	// FetchTenantsByID returns all tenants filtering by tenant id.
	FetchTenantsByID(page int32, pageSize int32, applicationID int64, tenantID string) ([]azmodels.Tenant, error)
	// FetchTenantsByName returns all tenants filtering by name.
	FetchTenantsByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.Tenant, error)
	// FetchTenantsBy returns all tenants filtering by tenant id and name.
	FetchTenantsBy(page int32, pageSize int32, applicationID int64, tenantID string, name string) ([]azmodels.Tenant, error)
}
