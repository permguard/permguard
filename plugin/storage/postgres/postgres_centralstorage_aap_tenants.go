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

package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

const (
	TenantDefaultName = "default"
)

// CreateTenant creates a new tenant.
func (s PostgresCentralStorageAAP) upsertTenant(db *gorm.DB, isCreate bool, tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	if tenant == nil {
		return nil, fmt.Errorf("storage: %w", azerrors.ErrInvalidInputParameter)
	}
	if err := validateAccountID("tenant", tenant.AccountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", tenant.AccountID, azerrors.ErrClientAccountID)
	}
	if err := validateName("tenant", tenant.Name); err != nil {
		return nil, fmt.Errorf("storage: invalid tenant name %q. %w", tenant.Name, azerrors.ErrClientName)
	}
	if !isCreate && tenant.Name == TenantDefaultName {
		return nil, fmt.Errorf("storage: tenant cannot be updated with a default name. %w", azerrors.ErrClientName)
	}

	var dbTenant Tenant
	var result *gorm.DB
	if isCreate {
		dbTenant = Tenant{
			AccountID: tenant.AccountID,
			Name:      tenant.Name,
		}
		result = db.Omit("CreatedAt", "UpdatedAt").Create(&dbTenant)
	} else {
		result = db.Where("account_id = ?", tenant.AccountID).Where("tenant_id = ?", tenant.TenantID).First(&dbTenant)
		if result.RowsAffected == 0 {
			return nil, fmt.Errorf("storage: tenant cannot be retrieved. %w", azerrors.ErrStorageNotFound)
		}
		dbTenant.Name = tenant.Name
		result = db.Omit("CreatedAt", "UpdatedAt").Where("tenant_id = ?", tenant.TenantID).Updates(&dbTenant)
	}
	if result.RowsAffected == 0 || result.Error != nil {
		pgErr, ok := result.Error.(*pgconn.PgError)
		if ok && pgErr.Code == "23505" {
			return nil, fmt.Errorf("storage: tenant cannot be created because of a duplicated name %w", azerrors.ErrStorageDuplicate)
		}
		return nil, fmt.Errorf("storage: tenant cannot be created. %w", azerrors.ErrStorageGeneric)
	}
	return mapTenantToAgentTenant(&dbTenant)
}

// CreateTenant creates a new tenant.
func (s PostgresCentralStorageAAP) CreateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertTenant(db, true, tenant)
}

// UpdateTenant updates an tenant.
func (s PostgresCentralStorageAAP) UpdateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.upsertTenant(db, false, tenant)
}

// DeleteTenant deletes an tenant.
func (s PostgresCentralStorageAAP) DeleteTenant(accountID int64, tenantID string) (*azmodels.Tenant, error) {
	if err := validateAccountID("tenant", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}
	if err := validateUUID("tenant", tenantID); err != nil {
		return nil, fmt.Errorf("storage: invalid tenant id %q. %w", tenantID, azerrors.ErrClientID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var dbTenant Tenant
	result := db.Where("account_id = ?", accountID).Where("tenant_id = ?", tenantID).First(&dbTenant)
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("storage: tenant cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	if dbTenant.Name == TenantDefaultName {
		return nil, fmt.Errorf("storage: default tenant cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	result = db.Where("account_id = ?", accountID).Where("tenant_id = ?", tenantID).Delete(dbTenant)
	if result.RowsAffected == 0 || result.Error != nil {
		return nil, fmt.Errorf("storage: tenant cannot be deleted. %w", azerrors.ErrStorageGeneric)
	}
	return mapTenantToAgentTenant(&dbTenant)
}

// GetAllTenants returns all tenants.
func (s PostgresCentralStorageAAP) GetAllTenants(accountID int64, fields map[string]any) ([]azmodels.Tenant, error) {
	if err := validateAccountID("tenant", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	var tenants []Tenant
	query := db.Where("account_id = ?", accountID)
	if _, ok := fields[azmodels.FieldTenantTenantID]; ok {
		tenantid, ok := fields[azmodels.FieldTenantTenantID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid tenant id. %w", azerrors.ErrClientUUID)
		}
		if err := validateUUID("tenant", tenantid); err != nil {
			return nil, fmt.Errorf("storage: invalid tenant id %q. %w", tenantid, azerrors.ErrClientUUID)
		}
		tenantid = "%" + tenantid + "%"
		query = query.Where("tenant_id::text LIKE ?", tenantid)
	}
	if _, ok := fields[azmodels.FieldTenantName]; ok {
		name, ok := fields[azmodels.FieldTenantName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid tenant name. %w", azerrors.ErrClientName)
		}
		if err := validateName("tenant", name); err != nil {
			return nil, fmt.Errorf("storage: invalid tenant name %q. %w", name, azerrors.ErrClientName)
		}
		name = "%" + name + "%"
		query = query.Where("name LIKE ?", name)
	}
	result := query.Find(&tenants)
	if result.Error != nil {
		return nil, fmt.Errorf("storage: tenant cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	dbTenants := make([]azmodels.Tenant, len(tenants))
	for i, a := range tenants {
		tenant, err := mapTenantToAgentTenant(&a)
		if err != nil {
			return nil, err
		}
		dbTenants[i] = *tenant
	}
	return dbTenants, nil
}
