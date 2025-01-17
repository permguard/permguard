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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azvalidators "github.com/permguard/permguard/pkg/core/validators"
)

const (
	// errorMessageIdentitySourceInvalidApplicationID is the error message identity source invalid application id.
	errorMessageIdentitySourceInvalidApplicationID = "storage: invalid client input - application id is not valid (id: %d)"
)

// UpsertIdentitySource creates or updates an identity source.
func (r *Repository) UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *IdentitySource) (*IdentitySource, error) {
	if identitySource == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity source data is missing or malformed (%s)", LogIdentitySourceEntry(identitySource)))
	}
	if err := azvalidators.ValidateCodeID("identitySource", identitySource.ApplicationID); err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentitySourceInvalidApplicationID, identitySource.ApplicationID))
	}
	if !isCreate && azvalidators.ValidateUUID("identitySource", identitySource.IdentitySourceID) != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity source id is not valid (%s)", LogIdentitySourceEntry(identitySource)))
	}
	if err := azvalidators.ValidateName("identitySource", identitySource.Name); err != nil {
		errorMessage := "storage: invalid client input - dentity source name is not valid (%s)"
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogIdentitySourceEntry(identitySource)))
	}

	applicationID := identitySource.ApplicationID
	identitySourceID := identitySource.IdentitySourceID
	identitySourceName := identitySource.Name
	var result sql.Result
	var err error
	if isCreate {
		identitySourceID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO identity_sources (application_id, identity_source_id, name) VALUES (?, ?, ?)", applicationID, identitySourceID, identitySourceName)
	} else {
		result, err = tx.Exec("UPDATE identity_sources SET name = ? WHERE application_id = ? and identity_source_id = ?", identitySourceName, applicationID, identitySourceID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "application id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s identity source - operation '%s-identity-source' encountered an issue (%s)", action, action, LogIdentitySourceEntry(identitySource)), err, params)
	}

	var dbIdentitySource IdentitySource
	err = tx.QueryRow("SELECT application_id, identity_source_id, created_at, updated_at, name FROM identity_sources WHERE application_id = ? and identity_source_id = ?", applicationID, identitySourceID).Scan(
		&dbIdentitySource.ApplicationID,
		&dbIdentitySource.IdentitySourceID,
		&dbIdentitySource.CreatedAt,
		&dbIdentitySource.UpdatedAt,
		&dbIdentitySource.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identity source - operation 'retrieve-created-identity-source' encountered an issue (%s)", LogIdentitySourceEntry(identitySource)), err)
	}
	return &dbIdentitySource, nil
}

// DeleteIdentitySource deletes an identity source.
func (r *Repository) DeleteIdentitySource(tx *sql.Tx, applicationID int64, identitySourceID string) (*IdentitySource, error) {
	if err := azvalidators.ValidateCodeID("identitySource", applicationID); err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentitySourceInvalidApplicationID, applicationID))
	}
	if err := azvalidators.ValidateUUID("identitySource", identitySourceID); err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity source id is not valid (id: %s)", identitySourceID))
	}

	var dbIdentitySource IdentitySource
	err := tx.QueryRow("SELECT application_id, identity_source_id, created_at, updated_at, name FROM identity_sources WHERE application_id = ? and identity_source_id = ?", applicationID, identitySourceID).Scan(
		&dbIdentitySource.ApplicationID,
		&dbIdentitySource.IdentitySourceID,
		&dbIdentitySource.CreatedAt,
		&dbIdentitySource.UpdatedAt,
		&dbIdentitySource.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - identity source id is not valid (id: %s)", identitySourceID), err)
	}
	res, err := tx.Exec("DELETE FROM identity_sources WHERE application_id = ? and identity_source_id = ?", applicationID, identitySourceID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity source - operation 'delete-identity-source' encountered an issue (id: %s)", identitySourceID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity source - operation 'delete-identity-source' could not find the identity source (id: %s)", identitySourceID), err)
	}
	return &dbIdentitySource, nil
}

// FetchIdentitySources retrieves identity sources.
func (r *Repository) FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]IdentitySource, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	if err := azvalidators.ValidateCodeID("identitySource", applicationID); err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientID, fmt.Sprintf(errorMessageIdentitySourceInvalidApplicationID, applicationID))
	}

	var dbIdentitySources []IdentitySource

	baseQuery := "SELECT * FROM identity_sources"
	var conditions []string
	var args []any

	conditions = append(conditions, "application_id = ?")
	args = append(args, applicationID)

	if filterID != nil {
		identitySourceID := *filterID
		if err := azvalidators.ValidateUUID("identitySource", identitySourceID); err != nil {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - identity source id is not valid (id: %s)", identitySourceID))
		}
		conditions = append(conditions, "identity_source_id = ?")
		args = append(args, identitySourceID)
	}

	if filterName != nil {
		identitySourceName := *filterName
		if err := azvalidators.ValidateName("identitySource", identitySourceName); err != nil {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - identity source name is not valid (name: %s)", identitySourceName))
		}
		identitySourceName = "%" + identitySourceName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, identitySourceName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY identity_source_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbIdentitySources, baseQuery, args...)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identity sources - operation 'retrieve-identity-sources' encountered an issue with parameters %v", args), err)
	}

	return dbIdentitySources, nil
}
