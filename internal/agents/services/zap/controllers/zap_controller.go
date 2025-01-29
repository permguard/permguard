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

package controllers

import (
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azStorage "github.com/permguard/permguard/pkg/agents/storage"
	azmodelszap "github.com/permguard/permguard/pkg/transport/models/zap"
)

// ZAPController is the controller for the ZAP service.
type ZAPController struct {
	ctx     *azservices.ServiceContext
	storage azStorage.ZAPCentralStorage
}

// Setup initializes the service.
func (s ZAPController) Setup() error {
	return nil
}

// NewZAPController creates a new ZAP controller.
func NewZAPController(serviceContext *azservices.ServiceContext, zapCentralStorage azStorage.ZAPCentralStorage) (*ZAPController, error) {
	service := ZAPController{
		ctx:     serviceContext,
		storage: zapCentralStorage,
	}
	return &service, nil
}

// CreateZone creates a new zone.
func (s ZAPController) CreateZone(zone *azmodelszap.Zone) (*azmodelszap.Zone, error) {
	return s.storage.CreateZone(zone)
}

// UpdateZone updates a zone.
func (s ZAPController) UpdateZone(zone *azmodelszap.Zone) (*azmodelszap.Zone, error) {
	return s.storage.UpdateZone(zone)
}

// DeleteZone delete a zone.
func (s ZAPController) DeleteZone(zoneID int64) (*azmodelszap.Zone, error) {
	return s.storage.DeleteZone(zoneID)
}

// FetchZones returns all zones filtering by search criteria.
func (s ZAPController) FetchZones(page int32, pageSize int32, fields map[string]any) ([]azmodelszap.Zone, error) {
	return s.storage.FetchZones(page, pageSize, fields)
}

// CreateIdentitySource creates a new identity source.
func (s ZAPController) CreateIdentitySource(identitySource *azmodelszap.IdentitySource) (*azmodelszap.IdentitySource, error) {
	return s.storage.CreateIdentitySource(identitySource)
}

// UpdateIdentitySource updates an identity source.
func (s ZAPController) UpdateIdentitySource(identitySource *azmodelszap.IdentitySource) (*azmodelszap.IdentitySource, error) {
	return s.storage.UpdateIdentitySource(identitySource)
}

// DeleteIdentitySource delete an identity source.
func (s ZAPController) DeleteIdentitySource(zoneID int64, identitySourceID string) (*azmodelszap.IdentitySource, error) {
	return s.storage.DeleteIdentitySource(zoneID, identitySourceID)
}

// FetchIdentitySources returns all identity sources filtering by search criteria.
func (s ZAPController) FetchIdentitySources(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]azmodelszap.IdentitySource, error) {
	return s.storage.FetchIdentitySources(page, pageSize, zoneID, fields)
}

// CreateIdentity creates a new identity.
func (s ZAPController) CreateIdentity(identity *azmodelszap.Identity) (*azmodelszap.Identity, error) {
	return s.storage.CreateIdentity(identity)
}

// UpdateIdentity updates an identity.
func (s ZAPController) UpdateIdentity(identity *azmodelszap.Identity) (*azmodelszap.Identity, error) {
	return s.storage.UpdateIdentity(identity)
}

// DeleteIdentity delete an identity.
func (s ZAPController) DeleteIdentity(zoneID int64, identityID string) (*azmodelszap.Identity, error) {
	return s.storage.DeleteIdentity(zoneID, identityID)
}

// FetchIdentities returns all identities filtering by search criteria.
func (s ZAPController) FetchIdentities(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]azmodelszap.Identity, error) {
	return s.storage.FetchIdentities(page, pageSize, zoneID, fields)
}

// CreateTenant creates a new tenant.
func (s ZAPController) CreateTenant(tenant *azmodelszap.Tenant) (*azmodelszap.Tenant, error) {
	return s.storage.CreateTenant(tenant)
}

// UpdateTenant updates a tenant.
func (s ZAPController) UpdateTenant(tenant *azmodelszap.Tenant) (*azmodelszap.Tenant, error) {
	return s.storage.UpdateTenant(tenant)
}

// DeleteTenant delete a tenant.
func (s ZAPController) DeleteTenant(zoneID int64, tenantID string) (*azmodelszap.Tenant, error) {
	return s.storage.DeleteTenant(zoneID, tenantID)
}

// FetchTenants returns all tenants filtering by search criteria.
func (s ZAPController) FetchTenants(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]azmodelszap.Tenant, error) {
	return s.storage.FetchTenants(page, pageSize, zoneID, fields)
}
