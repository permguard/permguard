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

	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/pkg/core/validators"
)

const (
	// errorMessageIdentityInvalidZoneID is the error message identity invalid zone id.
	errorMessageIdentityInvalidZoneID = "invalid client input - zone id is not valid (id: %d)"
)

// identitiesMap is a map of identity kinds to IDs.
var identitiesMap = map[string]int16{
	"user":       1,
	"role-actor": 2,
	"twin-actor": 3,
}

// ConvertIdentityKindToID converts an identity kind to an ID.
func ConvertIdentityKindToID(kind string) (int16, error) {
	cKey := strings.ToLower(kind)
	value, ok := identitiesMap[cKey]
	if !ok {
		return 0, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf("invalid client input - identity kind %s is not valid", kind))
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
func (r *Repository) UpsertIdentity(tx *sql.Tx, isCreate bool, identity *Identity) (*Identity, error) {
	if identity == nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf("invalid client input - identity data is missing or malformed (%s)", LogIdentityEntry(identity)))
	}
	if err := validators.ValidateCodeID("identity", identity.ZoneID); err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentityInvalidZoneID, identity.ZoneID), err)
	}
	if !isCreate && validators.ValidateUUID("identity", identity.IdentityID) != nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf("invalid client input - identity id is not valid (%s)", LogIdentityEntry(identity)))
	}
	if isCreate && validators.ValidateUUID("identity", identity.IdentitySourceID) != nil {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf("invalid client input - identity id is not valid (%s)", LogIdentityEntry(identity)))
	}
	if identity.Kind == identitiesMap["user"] {
		if err := validators.ValidateIdentityUserName("identity", identity.Name); err != nil {
			errorMessage := "invalid client input - identity name is not valid (%s)"
			return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogIdentityEntry(identity)), err)
		}
	} else {
		if err := validators.ValidateName("identity", identity.Name); err != nil {
			errorMessage := "invalid client input - identity name is not valid (%s)"
			return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogIdentityEntry(identity)), err)
		}
	}

	zoneID := identity.ZoneID
	identityID := identity.IdentityID
	identitySourceID := identity.IdentitySourceID
	kind := identity.Kind
	identityName := strings.ToLower(identity.Name)
	var result sql.Result
	var err error
	if isCreate {
		identityID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO identities (zone_id, identity_id, identity_source_id, kind, name) VALUES (?, ?, ?, ?, ?)", zoneID, identityID, identitySourceID, kind, identityName)
	} else {
		result, err = tx.Exec("UPDATE identities SET kind = ?, name = ? WHERE zone_id = ? and identity_id = ?", kind, identityName, zoneID, identityID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "zone id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s identity - operation '%s-identity' encountered an issue (%s)", action, action, LogIdentityEntry(identity)), err, params)
	}

	var dbIdentity Identity
	err = tx.QueryRow("SELECT zone_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE zone_id = ? and identity_id = ?", zoneID, identityID).Scan(
		&dbIdentity.ZoneID,
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
func (r *Repository) DeleteIdentity(tx *sql.Tx, zoneID int64, identityID string) (*Identity, error) {
	if err := validators.ValidateCodeID("identity", zoneID); err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentityInvalidZoneID, zoneID), err)
	}
	if err := validators.ValidateUUID("identity", identityID); err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientParameter, fmt.Sprintf("invalid client input - identity id is not valid (id: %s)", identityID), err)
	}
	var dbIdentity Identity
	err := tx.QueryRow("SELECT zone_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE zone_id = ? and identity_id = ?", zoneID, identityID).Scan(
		&dbIdentity.ZoneID,
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
	res, err := tx.Exec("DELETE FROM identities WHERE zone_id = ? and identity_id = ?", zoneID, identityID)
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
func (r *Repository) FetchIdentities(db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]Identity, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrClientPagination, fmt.Sprintf("invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	if err := validators.ValidateCodeID("identity", zoneID); err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientID, fmt.Sprintf(errorMessageIdentityInvalidZoneID, zoneID), err)
	}

	var dbIdentities []Identity

	baseQuery := "SELECT * FROM identities"
	var conditions []string
	var args []any

	conditions = append(conditions, "zone_id = ?")
	args = append(args, zoneID)

	if filterID != nil {
		identityID := *filterID
		if err := validators.ValidateUUID("identity", identityID); err != nil {
			return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientID, fmt.Sprintf("invalid client input - identity id is not valid (id: %s)", identityID), err)
		}
		conditions = append(conditions, "identity_id = ?")
		args = append(args, identityID)
	}

	if filterName != nil {
		identityName := *filterName
		if err := validators.ValidateIdentityUserName("identity", identityName); err != nil {
			if err := validators.ValidateName("identity", identityName); err != nil {
				return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrClientName, fmt.Sprintf("invalid client input - identity name is not valid (name: %s)", identityName), err)
			}
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
