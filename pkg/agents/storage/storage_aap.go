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
	azmodels "github.com/permguard/permguard/pkg/transport/models"
)

// AAPCentralStorage is the interface for the AAP central storage.
type AAPCentralStorage interface {
	// CreateApplication creates a new application.
	CreateApplication(application *azmodels.Application) (*azmodels.Application, error)
	// UpdateApplication updates an application.
	UpdateApplication(application *azmodels.Application) (*azmodels.Application, error)
	// DeleteApplication deletes an application.
	DeleteApplication(applicationID int64) (*azmodels.Application, error)
	// FetchApplications returns all applications filtering by search criteria.
	FetchApplications(page int32, pageSize int32, fields map[string]any) ([]azmodels.Application, error)

	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(applicationID int64, identitySourceID string) (*azmodels.IdentitySource, error)
	// FetchIdentitySources gets all identity sources.
	FetchIdentitySources(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodels.IdentitySource, error)

	// CreateIdentity creates a new identity.
	CreateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(applicationID int64, identityID string) (*azmodels.Identity, error)
	// FetchIdentities gets all identities.
	FetchIdentities(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodels.Identity, error)

	// CreateTenant creates a new tenant.
	CreateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(applicationID int64, tenantID string) (*azmodels.Tenant, error)
	// FetchTenants gets all tenants.
	FetchTenants(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodels.Tenant, error)
}
