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

	zapv1 "github.com/permguard/permguard/internal/agents/services/zap/endpoints/api/v1"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// CreateTenant creates a new tenant.
func (c *GrpcZAPClient) CreateTenant(zoneID int64, name string) (*zap.Tenant, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tenant, err := client.CreateTenant(context.Background(), &zapv1.TenantCreateRequest{ZoneID: zoneID, Name: name})
	if err != nil {
		return nil, err
	}
	return zapv1.MapGrpcTenantResponseToAgentTenant(tenant)
}

// UpdateTenant updates a tenant.
func (c *GrpcZAPClient) UpdateTenant(tenant *zap.Tenant) (*zap.Tenant, error) {
	if tenant == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientGeneric, "invalid tenant instance")
	}
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	updatedTenant, err := client.UpdateTenant(context.Background(), &zapv1.TenantUpdateRequest{
		TenantID: tenant.TenantID,
		ZoneID:   tenant.ZoneID,
		Name:     tenant.Name,
	})
	if err != nil {
		return nil, err
	}
	return zapv1.MapGrpcTenantResponseToAgentTenant(updatedTenant)
}

// DeleteTenant deletes a tenant.
func (c *GrpcZAPClient) DeleteTenant(zoneID int64, tenantID string) (*zap.Tenant, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tenant, err := client.DeleteTenant(context.Background(), &zapv1.TenantDeleteRequest{ZoneID: zoneID, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	return zapv1.MapGrpcTenantResponseToAgentTenant(tenant)
}

// FetchTenants returns all tenants.
func (c *GrpcZAPClient) FetchTenants(page int32, pageSize int32, zoneID int64) ([]zap.Tenant, error) {
	return c.FetchTenantsBy(page, pageSize, zoneID, "", "")
}

// FetchTenantsByID returns all tenants filtering by tenant id.
func (c *GrpcZAPClient) FetchTenantsByID(page int32, pageSize int32, zoneID int64, tenantID string) ([]zap.Tenant, error) {
	return c.FetchTenantsBy(page, pageSize, zoneID, tenantID, "")
}

// FetchTenantsByName returns all tenants filtering by name.
func (c *GrpcZAPClient) FetchTenantsByName(page int32, pageSize int32, zoneID int64, name string) ([]zap.Tenant, error) {
	return c.FetchTenantsBy(page, pageSize, zoneID, "", name)
}

// FetchTenantsBy returns all tenants filtering by tenant id and name.
func (c *GrpcZAPClient) FetchTenantsBy(page int32, pageSize int32, zoneID int64, tenantID string, name string) ([]zap.Tenant, error) {
	client, conn, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tenantFetchRequest := &zapv1.TenantFetchRequest{}
	tenantFetchRequest.Page = &page
	tenantFetchRequest.PageSize = &pageSize
	if zoneID > 0 {
		tenantFetchRequest.ZoneID = zoneID
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
	tenants := []zap.Tenant{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		tenant, err := zapv1.MapGrpcTenantResponseToAgentTenant(response)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, *tenant)
	}
	return tenants, nil
}
