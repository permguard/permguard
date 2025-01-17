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
	"context"
	"io"

	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelaap "github.com/permguard/permguard/pkg/transport/models/aap"
)

// CreateTenant creates a new tenant.
func (c *GrpcAAPClient) CreateTenant(applicationID int64, name string) (*azmodelaap.Tenant, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	tenant, err := client.CreateTenant(context.Background(), &azapiv1aap.TenantCreateRequest{ApplicationID: applicationID, Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcTenantResponseToAgentTenant(tenant)
}

// UpdateTenant updates a tenant.
func (c *GrpcAAPClient) UpdateTenant(tenant *azmodelaap.Tenant) (*azmodelaap.Tenant, error) {
	if tenant == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "invalid tenant instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedTenant, err := client.UpdateTenant(context.Background(), &azapiv1aap.TenantUpdateRequest{
		TenantID:      tenant.TenantID,
		ApplicationID: tenant.ApplicationID,
		Name:          tenant.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcTenantResponseToAgentTenant(updatedTenant)
}

// DeleteTenant deletes a tenant.
func (c *GrpcAAPClient) DeleteTenant(applicationID int64, tenantID string) (*azmodelaap.Tenant, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	tenant, err := client.DeleteTenant(context.Background(), &azapiv1aap.TenantDeleteRequest{ApplicationID: applicationID, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcTenantResponseToAgentTenant(tenant)
}

// FetchTenants returns all tenants.
func (c *GrpcAAPClient) FetchTenants(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Tenant, error) {
	return c.FetchTenantsBy(page, pageSize, applicationID, "", "")
}

// FetchTenantsByID returns all tenants filtering by tenant id.
func (c *GrpcAAPClient) FetchTenantsByID(page int32, pageSize int32, applicationID int64, tenantID string) ([]azmodelaap.Tenant, error) {
	return c.FetchTenantsBy(page, pageSize, applicationID, tenantID, "")
}

// FetchTenantsByName returns all tenants filtering by name.
func (c *GrpcAAPClient) FetchTenantsByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Tenant, error) {
	return c.FetchTenantsBy(page, pageSize, applicationID, "", name)
}

// FetchTenantsBy returns all tenants filtering by tenant id and name.
func (c *GrpcAAPClient) FetchTenantsBy(page int32, pageSize int32, applicationID int64, tenantID string, name string) ([]azmodelaap.Tenant, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	tenantFetchRequest := &azapiv1aap.TenantFetchRequest{}
	tenantFetchRequest.Page = &page
	tenantFetchRequest.PageSize = &pageSize
	if applicationID > 0 {
		tenantFetchRequest.ApplicationID = applicationID
	}
	if name != "" {
		tenantFetchRequest.Name = &name
	}
	if tenantID != "" {
		tenantFetchRequest.TenantID = &tenantID
	}
	stream, err := client.FetchTenants(context.Background(), tenantFetchRequest)
	if err != nil {
		return nil, err
	}
	tenants := []azmodelaap.Tenant{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		tenant, err := azapiv1aap.MapGrpcTenantResponseToAgentTenant(response)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, *tenant)
	}
	return tenants, nil
}
