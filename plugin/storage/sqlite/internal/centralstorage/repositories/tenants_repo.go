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

package repositories

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	"github.com/permguard/permguard/pkg/core/validators"
)

const (
	// errorMessageTenantInvalidZoneID is the error message tenant invalid zone id.
	errorMessageTenantInvalidZoneID = "storage: invalid client input - zone id is not valid (id: %d)"
)

// UpsertTenant creates or updates an tenant.
func (r *Repository) UpsertTenant(tx *sql.Tx, isCreate bool, tenant *Tenant) (*Tenant, error) {
	if tenant == nil {
		return nil, fmt.Errorf("storage: invalid client input - tenant data is missing or malformed (%s)", LogTenantEntry(tenant))
	}
	if err := validators.ValidateCodeID("tenant", tenant.ZoneID); err != nil {
		return nil, errors.Join(err, fmt.Errorf(errorMessageTenantInvalidZoneID, tenant.ZoneID))
	}
	if !isCreate && validators.ValidateUUID("tenant", tenant.TenantID) != nil {
		return nil, fmt.Errorf("storage: invalid client input - tenant id is not valid (%s)", LogTenantEntry(tenant))
	}
	if err := validators.ValidateName("tenant", tenant.Name); err != nil {
		return nil, errors.Join(err, fmt.Errorf("storage: invalid client input - tenant name is not valid (%s)", LogTenantEntry(tenant)))
	}

	zoneID := tenant.ZoneID
	tenantID := tenant.TenantID
	tenantName := tenant.Name
	var result sql.Result
	var err error
	if isCreate {
		tenantID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO tenants (zone_id, tenant_id, name) VALUES (?, ?, ?)", zoneID, tenantID, tenantName)
	} else {
		result, err = tx.Exec("UPDATE tenants SET name = ? WHERE zone_id = ? and tenant_id = ?", tenantName, zoneID, tenantID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "zone id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s tenant - operation '%s-tenant' encountered an issue (%s)", action, action, LogTenantEntry(tenant)), err, params)
	}

	var dbTenant Tenant
	err = tx.QueryRow("SELECT zone_id, tenant_id, created_at, updated_at, name FROM tenants WHERE zone_id = ? and tenant_id = ?", zoneID, tenantID).Scan(
		&dbTenant.ZoneID,
		&dbTenant.TenantID,
		&dbTenant.CreatedAt,
		&dbTenant.UpdatedAt,
		&dbTenant.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve tenant - operation 'retrieve-created-tenant' encountered an issue (%s)", LogTenantEntry(tenant)), err)
	}
	return &dbTenant, nil
}

// DeleteTenant deletes an tenant.
func (r *Repository) DeleteTenant(tx *sql.Tx, zoneID int64, tenantID string) (*Tenant, error) {
	if err := validators.ValidateCodeID("tenant", zoneID); err != nil {
		return nil, errors.Join(err, fmt.Errorf(errorMessageTenantInvalidZoneID, zoneID))
	}
	if err := validators.ValidateUUID("tenant", tenantID); err != nil {
		return nil, errors.Join(err, fmt.Errorf("storage: invalid client input - tenant id is not valid (id: %s)", tenantID))
	}

	var dbTenant Tenant
	err := tx.QueryRow("SELECT zone_id, tenant_id, created_at, updated_at, name FROM tenants WHERE zone_id = ? and tenant_id = ?", zoneID, tenantID).Scan(
		&dbTenant.ZoneID,
		&dbTenant.TenantID,
		&dbTenant.CreatedAt,
		&dbTenant.UpdatedAt,
		&dbTenant.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - tenant id is not valid (id: %s)", tenantID), err)
	}
	res, err := tx.Exec("DELETE FROM tenants WHERE zone_id = ? and tenant_id = ?", zoneID, tenantID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete tenant - operation 'delete-tenant' encountered an issue (id: %s)", tenantID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete tenant - operation 'delete-tenant' could not find the tenant (id: %s)", tenantID), err)
	}
	return &dbTenant, nil
}

// FetchTenants retrieves tenants.
func (r *Repository) FetchTenants(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]Tenant, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, fmt.Errorf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize)
	}
	if err := validators.ValidateCodeID("tenant", zoneID); err != nil {
		return nil, errors.Join(err, fmt.Errorf(errorMessageTenantInvalidZoneID, zoneID))
	}

	var dbTenants []Tenant

	baseQuery := "SELECT * FROM tenants"
	var conditions []string
	var args []any

	conditions = append(conditions, "zone_id = ?")
	args = append(args, zoneID)

	if filterID != nil {
		tenantID := *filterID
		if err := validators.ValidateUUID("tenant", tenantID); err != nil {
			return nil, errors.Join(err, fmt.Errorf("storage: invalid client input - tenant id is not valid (id: %s)", tenantID))
		}
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, tenantID)
	}

	if filterName != nil {
		tenantName := *filterName
		if err := validators.ValidateName("tenant", tenantName); err != nil {
			return nil, errors.Join(err, fmt.Errorf("storage: invalid client input - tenant name is not valid (name: %s)", tenantName))
		}
		tenantName = "%" + tenantName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, tenantName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY tenant_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbTenants, baseQuery, args...)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve tenants - operation 'retrieve-tenants' encountered an issue with parameters %v", args), err)
	}

	return dbTenants, nil
}
