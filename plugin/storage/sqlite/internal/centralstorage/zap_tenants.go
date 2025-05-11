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

	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/pkg/transport/models/zap"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	TenantDefaultName = "default"
)

// CreateTenant creates a new tenant.
func (s SQLiteCentralStorageZAP) CreateTenant(tenant *zap.Tenant) (*zap.Tenant, error) {
	if tenant == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, "invalid client input - tenant is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInTenant := &repos.Tenant{
		ZoneID: tenant.ZoneID,
		Name:   tenant.Name,
	}
	dbOutTenant, err := s.sqlRepo.UpsertTenant(tx, true, dbInTenant)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapTenantToAgentTenant(dbOutTenant)
}

// UpdateTenant updates a tenant.
func (s SQLiteCentralStorageZAP) UpdateTenant(tenant *zap.Tenant) (*zap.Tenant, error) {
	if tenant == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, "invalid client input - tenant is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInTenant := &repos.Tenant{
		TenantID: tenant.TenantID,
		ZoneID:   tenant.ZoneID,
		Name:     tenant.Name,
	}
	dbOutTenant, err := s.sqlRepo.UpsertTenant(tx, false, dbInTenant)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapTenantToAgentTenant(dbOutTenant)
}

// DeleteTenant deletes a tenant.
func (s SQLiteCentralStorageZAP) DeleteTenant(zoneID int64, tenantID string) (*zap.Tenant, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutTenant, err := s.sqlRepo.DeleteTenant(tx, zoneID, tenantID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapTenantToAgentTenant(dbOutTenant)
}

// FetchTenants returns all tenants.
func (s SQLiteCentralStorageZAP) FetchTenants(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]zap.Tenant, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientPagination, fmt.Sprintf("invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[zap.FieldTenantTenantID]; ok {
		tenantID, ok := fields[zap.FieldTenantTenantID].(string)
		if !ok {
			return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf("invalid client input - tenant id is not valid (tenant id: %s)", tenantID))
		}
		filterID = &tenantID
	}
	var filterName *string
	if _, ok := fields[zap.FieldTenantName]; ok {
		tenantName, ok := fields[zap.FieldTenantName].(string)
		if !ok {
			return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf("invalid client input - tenant name is not valid (tenant name: %s)", tenantName))
		}
		filterName = &tenantName
	}
	dbTenants, err := s.sqlRepo.FetchTenants(db, page, pageSize, zoneID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	tenants := make([]zap.Tenant, len(dbTenants))
	for i, a := range dbTenants {
		tenant, err := mapTenantToAgentTenant(&a)
		if err != nil {
			return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrStorageEntityMapping, fmt.Sprintf("failed to convert tenant entity (%s)", repos.LogTenantEntry(&a)), err)
		}
		tenants[i] = *tenant
	}
	return tenants, nil
}
