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

package facade

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	azvalidators "github.com/permguard/permguard/pkg/agents/storage/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// errorMessageTenantInvalidApplicationID is the error message tenant invalid application id.
	errorMessageTenantInvalidApplicationID = "storage: invalid client input - application id is not valid (id: %d)"
)

// UpsertTenant creates or updates an tenant.
func (r *Facade) UpsertTenant(tx *sql.Tx, isCreate bool, tenant *Tenant) (*Tenant, error) {
	if tenant == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant data is missing or malformed (%s)", LogTenantEntry(tenant)))
	}
	if err := azvalidators.ValidateCodeID("tenant", tenant.ApplicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageTenantInvalidApplicationID, tenant.ApplicationID))
	}
	if !isCreate && azvalidators.ValidateUUID("tenant", tenant.TenantID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant id is not valid (%s)", LogTenantEntry(tenant)))
	}
	if err := azvalidators.ValidateName("tenant", tenant.Name); err != nil {
		errorMessage := "storage: invalid client input - tenant name is not valid (%s)"
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogTenantEntry(tenant)))
	}

	applicationID := tenant.ApplicationID
	tenantID := tenant.TenantID
	tenantName := tenant.Name
	var result sql.Result
	var err error
	if isCreate {
		tenantID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO tenants (application_id, tenant_id, name) VALUES (?, ?, ?)", applicationID, tenantID, tenantName)
	} else {
		result, err = tx.Exec("UPDATE tenants SET name = ? WHERE application_id = ? and tenant_id = ?", tenantName, applicationID, tenantID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "application id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s tenant - operation '%s-tenant' encountered an issue (%s)", action, action, LogTenantEntry(tenant)), err, params)
	}

	var dbTenant Tenant
	err = tx.QueryRow("SELECT application_id, tenant_id, created_at, updated_at, name FROM tenants WHERE application_id = ? and tenant_id = ?", applicationID, tenantID).Scan(
		&dbTenant.ApplicationID,
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
func (r *Facade) DeleteTenant(tx *sql.Tx, applicationID int64, tenantID string) (*Tenant, error) {
	if err := azvalidators.ValidateCodeID("tenant", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageTenantInvalidApplicationID, applicationID))
	}
	if err := azvalidators.ValidateUUID("tenant", tenantID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant id is not valid (id: %s)", tenantID))
	}

	var dbTenant Tenant
	err := tx.QueryRow("SELECT application_id, tenant_id, created_at, updated_at, name FROM tenants WHERE application_id = ? and tenant_id = ?", applicationID, tenantID).Scan(
		&dbTenant.ApplicationID,
		&dbTenant.TenantID,
		&dbTenant.CreatedAt,
		&dbTenant.UpdatedAt,
		&dbTenant.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - tenant id is not valid (id: %s)", tenantID), err)
	}
	res, err := tx.Exec("DELETE FROM tenants WHERE application_id = ? and tenant_id = ?", applicationID, tenantID)
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
func (r *Facade) FetchTenants(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]Tenant, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	if err := azvalidators.ValidateCodeID("tenant", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageTenantInvalidApplicationID, applicationID))
	}

	var dbTenants []Tenant

	baseQuery := "SELECT * FROM tenants"
	var conditions []string
	var args []any

	conditions = append(conditions, "application_id = ?")
	args = append(args, applicationID)

	if filterID != nil {
		tenantID := *filterID
		if err := azvalidators.ValidateUUID("tenant", tenantID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - tenant id is not valid (id: %s)", tenantID))
		}
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, tenantID)
	}

	if filterName != nil {
		tenantName := *filterName
		if err := azvalidators.ValidateName("tenant", tenantName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - tenant name is not valid (name: %s)", tenantName))
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
