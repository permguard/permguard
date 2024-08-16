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

package grpcclients

import (
	"context"
	"errors"

	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateTenant creates a new tenant.
func (c *GrpcAAPClient) CreateTenant(accountID int64, name string) (*azmodels.Tenant, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	tenant, err := client.CreateTenant(context.Background(), &azapiv1aap.TenantCreateRequest{AccountID: accountID, Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcTenantResponseToAgentTenant(tenant)
}

// UpdateTenant updates a tenant.
func (c *GrpcAAPClient) UpdateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	if tenant == nil {
		return nil, errors.New("client: invalid tenant instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedTenant, err := client.UpdateTenant(context.Background(), &azapiv1aap.TenantUpdateRequest{
		TenantID:  tenant.TenantID,
		AccountID: tenant.AccountID,
		Name:      tenant.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcTenantResponseToAgentTenant(updatedTenant)
}

// DeleteTenant deletes a tenant.
func (c *GrpcAAPClient) DeleteTenant(accountID int64, tenantID string) (*azmodels.Tenant, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	tenant, err := client.DeleteTenant(context.Background(), &azapiv1aap.TenantDeleteRequest{AccountID: accountID, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcTenantResponseToAgentTenant(tenant)
}

// GetAllTenants returns all the tenants.
func (c *GrpcAAPClient) GetAllTenants(accountID int64) ([]azmodels.Tenant, error) {
	return c.GetTenantsBy(accountID, "", "")
}

// GetTenantsByID returns all tenants filtering by tenant id.
func (c *GrpcAAPClient) GetTenantsByID(accountID int64, tenantID string) ([]azmodels.Tenant, error) {
	return c.GetTenantsBy(accountID, tenantID, "")
}

// GetTenantsByName returns all tenants filtering by name.
func (c *GrpcAAPClient) GetTenantsByName(accountID int64, name string) ([]azmodels.Tenant, error) {
	return c.GetTenantsBy(accountID, "", name)
}

// GetTenantsBy returns all tenants filtering by tenant id and name.
func (c *GrpcAAPClient) GetTenantsBy(accountID int64, tenantID string, name string) ([]azmodels.Tenant, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	tenantGetRequest := &azapiv1aap.TenantGetRequest{}
	if accountID > 0 {
		tenantGetRequest.AccountID = accountID
	}
	if name != "" {
		tenantGetRequest.Name = &name
	}
	if tenantID != "" {
		tenantGetRequest.TenantID = &tenantID
	}
	tenantList, err := client.GetAllTenants(context.Background(), tenantGetRequest)
	if err != nil {
		return nil, err
	}
	tenants := make([]azmodels.Tenant, len(tenantList.Tenants))
	for i, tenant := range tenantList.Tenants {
		tenant, err := azapiv1aap.MapGrpcTenantResponseToAgentTenant(tenant)
		if err != nil {
			return nil, err
		}
		tenants[i] = *tenant
	}
	return tenants, nil
}
