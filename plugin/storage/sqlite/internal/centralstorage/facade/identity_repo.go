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
	// errorMessageIdentityInvalidApplicationID is the error message identity invalid application id.
	errorMessageIdentityInvalidApplicationID = "storage: invalid client input - application id is not valid (id: %d)"
)

// identitiesMap is a map of identity kinds to IDs.
var identitiesMap = map[string]int16{
	"user":  1,
	"actor": 2,
}

// ConvertIdentityKindToID converts an identity kind to an ID.
func ConvertIdentityKindToID(kind string) (int16, error) {
	cKey := strings.ToLower(kind)
	value, ok := identitiesMap[cKey]
	if !ok {
		return 0, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity kind %s is not valid", kind))
	}
	return value, nil
}

// ConvertIdentityKindToString converts an identity kind to a string.
func ConvertIdentityKindToString(id int16) (string, error) {
	for k, v := range identitiesMap {
		if v == id {
			return k, nil
		}
	}
	return "", nil
}

// UpsertIdentity creates or updates an identity.
func (r *Facade) UpsertIdentity(tx *sql.Tx, isCreate bool, identity *Identity) (*Identity, error) {
	if identity == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity data is missing or malformed (%s)", LogIdentityEntry(identity)))
	}
	if err := azvalidators.ValidateCodeID("identity", identity.ApplicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentityInvalidApplicationID, identity.ApplicationID))
	}
	if !isCreate && azvalidators.ValidateUUID("identity", identity.IdentityID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity id is not valid (%s)", LogIdentityEntry(identity)))
	}
	if isCreate && azvalidators.ValidateUUID("identity", identity.IdentitySourceID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity id is not valid (%s)", LogIdentityEntry(identity)))
	}
	if identity.Kind == identitiesMap["user"] {
		if err := azvalidators.ValidateIdentityUserName("identity", identity.Name); err != nil {
			errorMessage := "storage: invalid client input - identity name is not valid (%s)"
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogIdentityEntry(identity)))
		}
	} else {
		if err := azvalidators.ValidateName("identity", identity.Name); err != nil {
			errorMessage := "storage: invalid client input - identity name is not valid (%s)"
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogIdentityEntry(identity)))
		}
	}

	applicationID := identity.ApplicationID
	identityID := identity.IdentityID
	identitySourceID := identity.IdentitySourceID
	kind := identity.Kind
	identityName := strings.ToLower(identity.Name)
	var result sql.Result
	var err error
	if isCreate {
		identityID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO identities (application_id, identity_id, identity_source_id, kind, name) VALUES (?, ?, ?, ?, ?)", applicationID, identityID, identitySourceID, kind, identityName)
	} else {
		result, err = tx.Exec("UPDATE identities SET kind = ?, name = ? WHERE application_id = ? and identity_id = ?", kind, identityName, applicationID, identityID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "application id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s identity - operation '%s-identity' encountered an issue (%s)", action, action, LogIdentityEntry(identity)), err, params)
	}

	var dbIdentity Identity
	err = tx.QueryRow("SELECT application_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE application_id = ? and identity_id = ?", applicationID, identityID).Scan(
		&dbIdentity.ApplicationID,
		&dbIdentity.IdentityID,
		&dbIdentity.CreatedAt,
		&dbIdentity.UpdatedAt,
		&dbIdentity.IdentitySourceID,
		&dbIdentity.Kind,
		&dbIdentity.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identity - operation 'retrieve-created-identity' encountered an issue (%s)", LogIdentityEntry(identity)), err)
	}
	return &dbIdentity, nil
}

// DeleteIdentity deletes an identity.
func (r *Facade) DeleteIdentity(tx *sql.Tx, applicationID int64, identityID string) (*Identity, error) {
	if err := azvalidators.ValidateCodeID("identity", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentityInvalidApplicationID, applicationID))
	}
	if err := azvalidators.ValidateUUID("identity", identityID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity id is not valid (id: %s)", identityID))
	}
	var dbIdentity Identity
	err := tx.QueryRow("SELECT application_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE application_id = ? and identity_id = ?", applicationID, identityID).Scan(
		&dbIdentity.ApplicationID,
		&dbIdentity.IdentityID,
		&dbIdentity.CreatedAt,
		&dbIdentity.UpdatedAt,
		&dbIdentity.IdentitySourceID,
		&dbIdentity.Kind,
		&dbIdentity.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - identity id is not valid (id: %s)", identityID), err)
	}
	res, err := tx.Exec("DELETE FROM identities WHERE application_id = ? and identity_id = ?", applicationID, identityID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity - operation 'delete-identity' encountered an issue (id: %s)", identityID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity - operation 'delete-identity' could not find the identity (id: %s)", identityID), err)
	}
	return &dbIdentity, nil
}

// FetchIdentities retrieves identities.
func (r *Facade) FetchIdentities(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]Identity, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	if err := azvalidators.ValidateCodeID("identity", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageIdentityInvalidApplicationID, applicationID))
	}

	var dbIdentities []Identity

	baseQuery := "SELECT * FROM identities"
	var conditions []string
	var args []any

	conditions = append(conditions, "application_id = ?")
	args = append(args, applicationID)

	if filterID != nil {
		identityID := *filterID
		if err := azvalidators.ValidateUUID("identity", identityID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - identity id is not valid (id: %s)", identityID))
		}
		conditions = append(conditions, "identity_id = ?")
		args = append(args, identityID)
	}

	if filterName != nil {
		identityName := *filterName
		if err := azvalidators.ValidateIdentityUserName("identity", identityName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - identity name is not valid (name: %s)", identityName))
		}
		identityName = "%" + identityName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, identityName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY identity_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbIdentities, baseQuery, args...)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identities - operation 'retrieve-identities' encountered an issue with parameters %v", args), err)
	}

	return dbIdentities, nil
}
