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

	azvalidators "github.com/permguard/permguard/pkg/agents/storage/validators"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

const (
	// errorMessageIdentitySourceInvalidAccountID is the error message identity source invalid account id.
	errorMessageIdentitySourceInvalidAccountID = "storage: invalid client input - account id is not valid (id: %d)."
)

// UpsertIdentitySource creates or updates an identity source.
func (r *Repo) UpsertIdentitySource(tx *sql.Tx, isCreate bool, identitySource *IdentitySource) (*IdentitySource, error) {
	if identitySource == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity source data is missing or malformed (%s).", LogIdentitySourceEntry(identitySource)))
	}
	if err := azvalidators.ValidateAccountID("identitySource", identitySource.AccountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentitySourceInvalidAccountID, identitySource.AccountID))
	}
	if !isCreate && azvalidators.ValidateUUID("identitySource", identitySource.IdentitySourceID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity source id is not valid (%s).", LogIdentitySourceEntry(identitySource)))
	}
	if err := azvalidators.ValidateName("identitySource", identitySource.Name); err != nil {
		errorMessage := "storage: invalid client input - dentity source name is not valid (%s)."
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogIdentitySourceEntry(identitySource)))
	}

	accountID := identitySource.AccountID
	identitySourceID := identitySource.IdentitySourceID
	identitySourceName := identitySource.Name
	var result sql.Result
	var err error
	if isCreate {
		identitySourceID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO identity_sources (account_id, identity_source_id, name) VALUES (?, ?, ?)", accountID, identitySourceID, identitySourceName)
	} else {
		result, err = tx.Exec("UPDATE identity_sources SET name = ? WHERE account_id = ? and identity_source_id = ?", identitySourceName, accountID, identitySourceID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "account id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s identity source - operation '%s-identity-source' encountered an issue (%s).", action, action, LogIdentitySourceEntry(identitySource)), err, params)
	}

	var dbIdentitySource IdentitySource
	err = tx.QueryRow("SELECT account_id, identity_source_id, created_at, updated_at, name FROM identity_sources WHERE account_id = ? and identity_source_id = ?", accountID, identitySourceID).Scan(
		&dbIdentitySource.AccountID,
		&dbIdentitySource.IdentitySourceID,
		&dbIdentitySource.CreatedAt,
		&dbIdentitySource.UpdatedAt,
		&dbIdentitySource.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identity source - operation 'retrieve-created-identity-source' encountered an issue (%s).", LogIdentitySourceEntry(identitySource)), err)
	}
	return &dbIdentitySource, nil
}

// DeleteIdentitySource deletes an identity source.
func (r *Repo) DeleteIdentitySource(tx *sql.Tx, accountID int64, identitySourceID string) (*IdentitySource, error) {
	if err := azvalidators.ValidateAccountID("identitySource", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentitySourceInvalidAccountID, accountID))
	}
	if err := azvalidators.ValidateUUID("identitySource", identitySourceID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity source id is not valid (id: %s).", identitySourceID))
	}

	var dbIdentitySource IdentitySource
	err := tx.QueryRow("SELECT account_id, identity_source_id, created_at, updated_at, name FROM identity_sources WHERE account_id = ? and identity_source_id = ?", accountID, identitySourceID).Scan(
		&dbIdentitySource.AccountID,
		&dbIdentitySource.IdentitySourceID,
		&dbIdentitySource.CreatedAt,
		&dbIdentitySource.UpdatedAt,
		&dbIdentitySource.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - identity source id is not valid (id: %s).", identitySourceID), err)
	}
	res, err := tx.Exec("DELETE FROM identity_sources WHERE account_id = ? and identity_source_id = ?", accountID, identitySourceID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity source - operation 'delete-identity-source' encountered an issue (id: %s).", identitySourceID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity source - operation 'delete-identity-source' could not find the identity source (id: %s).", identitySourceID), err)
	}
	return &dbIdentitySource, nil
}

// FetchIdentitySources retrieves identity sources.
func (r *Repo) FetchIdentitySources(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]IdentitySource, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid.", page, pageSize))
	}
	if err := azvalidators.ValidateAccountID("identitySource", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageIdentitySourceInvalidAccountID, accountID))
	}

	var dbIdentitySources []IdentitySource

	baseQuery := "SELECT * FROM identity_sources"
	var conditions []string
	var args []interface{}

	conditions = append(conditions, "account_id = ?")
	args = append(args, accountID)

	if filterID != nil {
		identitySourceID := *filterID
		if err := azvalidators.ValidateUUID("identitySource", identitySourceID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - identity source id is not valid (id: %s).", identitySourceID))
		}
		conditions = append(conditions, "identity_source_id = ?")
		args = append(args, identitySourceID)
	}

	if filterName != nil {
		identitySourceName := *filterName
		if err := azvalidators.ValidateName("identitySource", identitySourceName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - identity source name is not valid (name: %s).", identitySourceName))
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
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identity sources - operation 'retrieve-identity-sources' encountered an issue with parameters %v.", args), err)
	}

	return dbIdentitySources, nil
}
