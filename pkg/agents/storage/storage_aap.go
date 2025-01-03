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
	azmodelsaap "github.com/permguard/permguard/pkg/transport/models/aap"
)

// AAPCentralStorage is the interface for the AAP central storage.
type AAPCentralStorage interface {
	// CreateApplication creates a new application.
	CreateApplication(application *azmodelsaap.Application) (*azmodelsaap.Application, error)
	// UpdateApplication updates an application.
	UpdateApplication(application *azmodelsaap.Application) (*azmodelsaap.Application, error)
	// DeleteApplication deletes an application.
	DeleteApplication(applicationID int64) (*azmodelsaap.Application, error)
	// FetchApplications returns all applications filtering by search criteria.
	FetchApplications(page int32, pageSize int32, fields map[string]any) ([]azmodelsaap.Application, error)

	// CreateIdentitySource creates a new identity source.
	CreateIdentitySource(identitySource *azmodelsaap.IdentitySource) (*azmodelsaap.IdentitySource, error)
	// UpdateIdentitySource updates an identity source.
	UpdateIdentitySource(identitySource *azmodelsaap.IdentitySource) (*azmodelsaap.IdentitySource, error)
	// DeleteIdentitySource deletes an identity source.
	DeleteIdentitySource(applicationID int64, identitySourceID string) (*azmodelsaap.IdentitySource, error)
	// FetchIdentitySources gets all identity sources.
	FetchIdentitySources(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodelsaap.IdentitySource, error)

	// CreateIdentity creates a new identity.
	CreateIdentity(identity *azmodelsaap.Identity) (*azmodelsaap.Identity, error)
	// UpdateIdentity updates an identity.
	UpdateIdentity(identity *azmodelsaap.Identity) (*azmodelsaap.Identity, error)
	// DeleteIdentity deletes an identity.
	DeleteIdentity(applicationID int64, identityID string) (*azmodelsaap.Identity, error)
	// FetchIdentities gets all identities.
	FetchIdentities(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodelsaap.Identity, error)

	// CreateTenant creates a new tenant.
	CreateTenant(tenant *azmodelsaap.Tenant) (*azmodelsaap.Tenant, error)
	// UpdateTenant updates a tenant.
	UpdateTenant(tenant *azmodelsaap.Tenant) (*azmodelsaap.Tenant, error)
	// DeleteTenant deletes a tenant.
	DeleteTenant(applicationID int64, tenantID string) (*azmodelsaap.Tenant, error)
	// FetchTenants gets all tenants.
	FetchTenants(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodelsaap.Tenant, error)
}
