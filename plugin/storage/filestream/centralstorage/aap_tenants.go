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

package centralstorage

import (
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

const (
	TenantDefaultName = "default"
)

// CreateTenant creates a new tenant.
func (s FileStreamCentralStorageAAP) CreateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// UpdateTenant updates an tenant.
func (s FileStreamCentralStorageAAP) UpdateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// DeleteTenant deletes an tenant.
func (s FileStreamCentralStorageAAP) DeleteTenant(accountID int64, tenantID string) (*azmodels.Tenant, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// GetAllTenants returns all tenants.
func (s FileStreamCentralStorageAAP) GetAllTenants(accountID int64, fields map[string]any) ([]azmodels.Tenant, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}
