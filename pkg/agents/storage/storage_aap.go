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

package storage

import (
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// ZAPCentralStorage is the interface for the ZAP central storage.
type ZAPCentralStorage interface {
	// CreateZone creates a new zone.
	CreateZone(zone *zap.Zone) (*zap.Zone, error)
	// UpdateZone updates a zone.
	UpdateZone(zone *zap.Zone) (*zap.Zone, error)
	// DeleteZone deletes a zone.
	DeleteZone(zoneID int64) (*zap.Zone, error)
	// FetchZones returns all zones filtering by search criteria.
	FetchZones(page int32, pageSize int32, fields map[string]any) ([]zap.Zone, error)

	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(identitySource *zap.IdentitySource) (*zap.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *zap.IdentitySource) (*zap.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(zoneID int64, identitySourceID string) (*zap.IdentitySource, error)
	// FetchIdentitySources gets all identity sources.
	FetchIdentitySources(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.IdentitySource, error)

	// CreateIdentity creates a new identity.
	CreateIdentity(identity *zap.Identity) (*zap.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *zap.Identity) (*zap.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(zoneID int64, identityID string) (*zap.Identity, error)
	// FetchIdentities gets all identities.
	FetchIdentities(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.Identity, error)

	// CreateTenant creates a new tenant.
	CreateTenant(tenant *zap.Tenant) (*zap.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *zap.Tenant) (*zap.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(zoneID int64, tenantID string) (*zap.Tenant, error)
	// FetchTenants gets all tenants.
	FetchTenants(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.Tenant, error)
}
