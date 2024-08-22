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
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azivalidators "github.com/permguard/permguard/plugin/storage/sqlite/internal/extensions/validators"
)

const (
	// errorMessageTenantInvalidAccountID is the error message tenant invalid account id.
	errorMessageTenantInvalidAccountID = "storage: invalid client input - account id is not valid (id: %d)."
)

// UpsertTenant creates or updates an tenant.
func (r *Repo) UpsertTenant(tx *sql.Tx, isCreate bool, tenant *Tenant) (*Tenant, error) {
	if tenant == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant data is missing or malformed (%s).", LogTenantEntry(tenant)))
	}
	if err := azivalidators.ValidateAccountID("tenant", tenant.AccountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageTenantInvalidAccountID, tenant.AccountID))
	}
	if !isCreate && azivalidators.ValidateUUID("tenant", tenant.TenantID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant id is not valid (%s).", LogTenantEntry(tenant)))
	}
	if err := azivalidators.ValidateName("tenant", tenant.Name); err != nil {
		errorMessage := "storage: invalid client input - either tenant id or tenant name is not valid (%s)."
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogTenantEntry(tenant)))
	}

	accountID := tenant.AccountID
	tenantID := tenant.TenantID
	tenantName := tenant.Name
	var result sql.Result
	var err error
	if isCreate {
		tenantID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO tenants (account_id, tenant_id, name) VALUES (?, ?, ?)", accountID, tenantID, tenantName)
	} else {
		result, err = tx.Exec("UPDATE tenants SET name = ? WHERE account_id = ? and tenant_id = ?", tenantName, accountID, tenantID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to %s tenant - operation '%s-tenant' encountered an issue (%s).", action, action, LogTenantEntry(tenant)), err)
	}

	var dbTenant Tenant
	err = tx.QueryRow("SELECT account_id, tenant_id, created_at, updated_at, name FROM tenants WHERE account_id = ? and tenant_id = ?", accountID, tenantID).Scan(
		&dbTenant.AccountID,
		&dbTenant.TenantID,
		&dbTenant.CreatedAt,
		&dbTenant.UpdatedAt,
		&dbTenant.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve tenant - operation 'retrieve-created-tenant' encountered an issue (%s).", LogTenantEntry(tenant)), err)
	}
	return &dbTenant, nil
}

// DeleteTenant deletes an tenant.
func (r *Repo) DeleteTenant(tx *sql.Tx, accountID int64, tenantID string) (*Tenant, error) {
	if err := azivalidators.ValidateAccountID("tenant", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageTenantInvalidAccountID, accountID))
	}
	if err := azivalidators.ValidateUUID("tenant", tenantID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - tenant id is not valid (id: %s).", tenantID))
	}
	var dbTenant Tenant
	err := tx.QueryRow("SELECT account_id, tenant_id, created_at, updated_at, name FROM tenants WHERE account_id = ? and tenant_id = ?", accountID, tenantID).Scan(
		&dbTenant.AccountID,
		&dbTenant.TenantID,
		&dbTenant.CreatedAt,
		&dbTenant.UpdatedAt,
		&dbTenant.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - tenant id is not valid (id: %s).", tenantID), err)
	}
	res, err := tx.Exec("DELETE FROM tenants WHERE account_id = ? and tenant_id = ?", accountID, tenantID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete tenant - operation 'delete-tenant' encountered an issue (id: %s).", tenantID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete tenant - operation 'delete-tenant' encountered an issue (id: %s).", tenantID), err)
	}
	return &dbTenant, nil
}

// FetchTenants retrieves tenants.
func (r *Repo) FetchTenants(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]Tenant, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid.", page, pageSize))
	}
	if err := azivalidators.ValidateAccountID("tenant", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageTenantInvalidAccountID, accountID))
	}

	var dbTenants []Tenant

	baseQuery := "SELECT * FROM tenants"
	var conditions []string
	var args []interface{}

	conditions = append(conditions, "account_id = ?")
	args = append(args, accountID)

	if filterID != nil {
		tenantID := *filterID
		if err := azivalidators.ValidateUUID("tenant", tenantID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - tenant id is not valid (id: %s).", tenantID))
		}
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, tenantID)
	}

	if filterName != nil {
		tenantName := *filterName
		if err := azivalidators.ValidateName("tenant", tenantName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - tenant name is not valid (name: %s).", tenantName))
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
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve tenants - operation 'retrieve-tenants' encountered an issue with parameters %v.", args), err)
	}

	return dbTenants, nil
}
