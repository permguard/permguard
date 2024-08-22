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
	"fmt"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	TenantDefaultName = "default"
)

// CreateTenant creates a new tenant.
func (s SQLiteCentralStorageAAP) CreateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	if tenant == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - tenant is nil.")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInTenant := &azirepos.Tenant{
		AccountID: tenant.AccountID,
		Name:      tenant.Name,
	}
	dbOutTenant, err := s.sqlRepo.UpsertTenant(tx, true, dbInTenant)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapTenantToAgentTenant(dbOutTenant)
}

// UpdateTenant updates a tenant.
func (s SQLiteCentralStorageAAP) UpdateTenant(tenant *azmodels.Tenant) (*azmodels.Tenant, error) {
	if tenant == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - tenant is nil.")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInTenant := &azirepos.Tenant{
		TenantID:  tenant.TenantID,
		AccountID: tenant.AccountID,
		Name:      tenant.Name,
	}
	dbOutTenant, err := s.sqlRepo.UpsertTenant(tx, false, dbInTenant)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapTenantToAgentTenant(dbOutTenant)
}

// DeleteTenant deletes a tenant.
func (s SQLiteCentralStorageAAP) DeleteTenant(accountID int64, tenantID string) (*azmodels.Tenant, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutTenant, err := s.sqlRepo.DeleteTenant(tx, accountID, tenantID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapTenantToAgentTenant(dbOutTenant)
}

// FetchTenants returns all tenants.
func (s SQLiteCentralStorageAAP) FetchTenants(page int32, pageSize int32, accountID int64, fields map[string]any) ([]azmodels.Tenant, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid.", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[azmodels.FieldTenantTenantID]; ok {
		tenantID, ok := fields[azmodels.FieldTenantTenantID].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant id is not valid (tenant id: %s).", tenantID))
		}
		filterID = &tenantID
	}
	var filterName *string
	if _, ok := fields[azmodels.FieldTenantName]; ok {
		tenantName, ok := fields[azmodels.FieldTenantName].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant name is not valid (tenant name: %s).", tenantName))
		}
		filterName = &tenantName
	}
	dbTenants, err := s.sqlRepo.FetchTenants(db, page, pageSize, accountID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	tenants := make([]azmodels.Tenant, len(dbTenants))
	for i, a := range dbTenants {
		tenant, err := mapTenantToAgentTenant(&a)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageEntityMapping, fmt.Sprintf("storage: failed to convert tenant entity (%s).", azirepos.LogTenantEntry(&a)))
		}
		tenants[i] = *tenant
	}
	return tenants, nil
}
