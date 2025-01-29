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
	azmodelzap "github.com/permguard/permguard/pkg/transport/models/zap"
)

// GrpcZAPClient is the gRPC ZAP client servicer.
type GrpcZAPClient interface {
	// CreateZone creates a new zone.
	CreateZone(name string) (*azmodelzap.Zone, error)
	// UpdateZone updates a zone.
	UpdateZone(zone *azmodelzap.Zone) (*azmodelzap.Zone, error)
	// DeleteZone deletes a zone.
	DeleteZone(zoneID int64) (*azmodelzap.Zone, error)
	// FetchZones fetches zones.
	FetchZones(page int32, pageSize int32) ([]azmodelzap.Zone, error)
	// FetchZonesByID fetches zones by ID.
	FetchZonesByID(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Zone, error)
	// FetchZonesByName fetches zones by name.
	FetchZonesByName(page int32, pageSize int32, name string) ([]azmodelzap.Zone, error)
	// FetchZonesBy fetches zones by.
	FetchZonesBy(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Zone, error)
	// CreateIdentity creates a new identity.
	CreateIdentity(zoneID int64, identitySourceID string, kind string, name string) (*azmodelzap.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *azmodelzap.Identity) (*azmodelzap.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(zoneID int64, identityID string) (*azmodelzap.Identity, error)
	// FetchIdentities returns all identities.
	FetchIdentities(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Identity, error)
	// FetchIdentitiesByID returns all identities filtering by identity id.
	FetchIdentitiesByID(page int32, pageSize int32, zoneID int64, identityID string) ([]azmodelzap.Identity, error)
	// FetchIdentitiesByEmail returns all identities filtering by name.
	FetchIdentitiesByEmail(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Identity, error)
	// FetchIdentitiesBy returns all identities filtering by all criteria.
	FetchIdentitiesBy(page int32, pageSize int32, zoneID int64, identitySourceID string, identityID string, kind string, name string) ([]azmodelzap.Identity, error)
	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(zoneID int64, name string) (*azmodelzap.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *azmodelzap.IdentitySource) (*azmodelzap.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(zoneID int64, identitySourceID string) (*azmodelzap.IdentitySource, error)
	// FetchIdentitySources returns all identity sources.
	FetchIdentitySources(page int32, pageSize int32, zoneID int64) ([]azmodelzap.IdentitySource, error)
	// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
	FetchIdentitySourcesByID(page int32, pageSize int32, zoneID int64, identitySourceID string) ([]azmodelzap.IdentitySource, error)
	// FetchIdentitySourcesByName returns all identity sources filtering by name.
	FetchIdentitySourcesByName(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.IdentitySource, error)
	// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
	FetchIdentitySourcesBy(page int32, pageSize int32, zoneID int64, identitySourceID string, name string) ([]azmodelzap.IdentitySource, error)
	// CreateTenant creates a tenant.
	CreateTenant(zoneID int64, name string) (*azmodelzap.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *azmodelzap.Tenant) (*azmodelzap.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(zoneID int64, tenantID string) (*azmodelzap.Tenant, error)
	// FetchTenants returns all tenants.
	FetchTenants(page int32, pageSize int32, zoneID int64) ([]azmodelzap.Tenant, error)
	// FetchTenantsByID returns all tenants filtering by tenant id.
	FetchTenantsByID(page int32, pageSize int32, zoneID int64, tenantID string) ([]azmodelzap.Tenant, error)
	// FetchTenantsByName returns all tenants filtering by name.
	FetchTenantsByName(page int32, pageSize int32, zoneID int64, name string) ([]azmodelzap.Tenant, error)
	// FetchTenantsBy returns all tenants filtering by tenant id and name.
	FetchTenantsBy(page int32, pageSize int32, zoneID int64, tenantID string, name string) ([]azmodelzap.Tenant, error)
}
