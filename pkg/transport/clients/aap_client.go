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
	azmodelaap "github.com/permguard/permguard/pkg/transport/models/aap"
)

// GrpcAAPClient is the gRPC AAP client servicer.
type GrpcAAPClient interface {
	// CreateApplication creates a new application.
	CreateApplication(name string) (*azmodelaap.Application, error)
	// UpdateApplication updates an application.
	UpdateApplication(application *azmodelaap.Application) (*azmodelaap.Application, error)
	// DeleteApplication deletes an application.
	DeleteApplication(applicationID int64) (*azmodelaap.Application, error)
	// FetchApplications fetches applications.
	FetchApplications(page int32, pageSize int32) ([]azmodelaap.Application, error)
	// FetchApplicationsByID fetches applications by ID.
	FetchApplicationsByID(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Application, error)
	// FetchApplicationsByName fetches applications by name.
	FetchApplicationsByName(page int32, pageSize int32, name string) ([]azmodelaap.Application, error)
	// FetchApplicationsBy fetches applications by.
	FetchApplicationsBy(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Application, error)
	// CreateIdentity creates a new identity.
	CreateIdentity(applicationID int64, identitySourceID string, kind string, name string) (*azmodelaap.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *azmodelaap.Identity) (*azmodelaap.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(applicationID int64, identityID string) (*azmodelaap.Identity, error)
	// FetchIdentities returns all identities.
	FetchIdentities(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Identity, error)
	// FetchIdentitiesByID returns all identities filtering by identity id.
	FetchIdentitiesByID(page int32, pageSize int32, applicationID int64, identityID string) ([]azmodelaap.Identity, error)
	// FetchIdentitiesByEmail returns all identities filtering by name.
	FetchIdentitiesByEmail(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Identity, error)
	// FetchIdentitiesBy returns all identities filtering by all criteria.
	FetchIdentitiesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodelaap.Identity, error)
	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(applicationID int64, name string) (*azmodelaap.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *azmodelaap.IdentitySource) (*azmodelaap.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(applicationID int64, identitySourceID string) (*azmodelaap.IdentitySource, error)
	// FetchIdentitySources returns all identity sources.
	FetchIdentitySources(page int32, pageSize int32, applicationID int64) ([]azmodelaap.IdentitySource, error)
	// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
	FetchIdentitySourcesByID(page int32, pageSize int32, applicationID int64, identitySourceID string) ([]azmodelaap.IdentitySource, error)
	// FetchIdentitySourcesByName returns all identity sources filtering by name.
	FetchIdentitySourcesByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.IdentitySource, error)
	// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
	FetchIdentitySourcesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, name string) ([]azmodelaap.IdentitySource, error)
	// CreateTenant creates a tenant.
	CreateTenant(applicationID int64, name string) (*azmodelaap.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *azmodelaap.Tenant) (*azmodelaap.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(applicationID int64, tenantID string) (*azmodelaap.Tenant, error)
	// FetchTenants returns all tenants.
	FetchTenants(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Tenant, error)
	// FetchTenantsByID returns all tenants filtering by tenant id.
	FetchTenantsByID(page int32, pageSize int32, applicationID int64, tenantID string) ([]azmodelaap.Tenant, error)
	// FetchTenantsByName returns all tenants filtering by name.
	FetchTenantsByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Tenant, error)
	// FetchTenantsBy returns all tenants filtering by tenant id and name.
	FetchTenantsBy(page int32, pageSize int32, applicationID int64, tenantID string, name string) ([]azmodelaap.Tenant, error)
}
