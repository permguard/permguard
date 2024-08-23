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
	// errorMessageIdentityInvalidAccountID is the error message identity invalid account id.
	errorMessageIdentityInvalidAccountID = "storage: invalid client input - account id is not valid (id: %d)."
)

// identitiesMap is a map of identity kinds to IDs.
var identitiesMap = map[string]int16{
	"user": 1,
	"role": 2,
}

// ConvertIdentityKindToID converts an identity kind to an ID.
func ConvertIdentityKindToID(kind string) (int16, error) {
	cKey := strings.ToLower(kind)
	value, ok := identitiesMap[cKey]
	if !ok {
		return 0, fmt.Errorf("storage: invalid identity kind. %w", azerrors.ErrClientGeneric)
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
func (r *Repo) UpsertIdentity(tx *sql.Tx, isCreate bool, identity *Identity) (*Identity, error) {
	if identity == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity data is missing or malformed (%s).", LogIdentityEntry(identity)))
	}
	if err := azivalidators.ValidateAccountID("identity", identity.AccountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentityInvalidAccountID, identity.AccountID))
	}
	if !isCreate && azivalidators.ValidateUUID("identity", identity.IdentityID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity id is not valid (%s).", LogIdentityEntry(identity)))
	}
	if isCreate && azivalidators.ValidateUUID("identity", identity.IdentitySourceID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity id is not valid (%s).", LogIdentityEntry(identity)))
	}
	if err := azivalidators.ValidateName("identity", identity.Name); err != nil {
		errorMessage := "storage: invalid client input - either identity id or identity name is not valid (%s)."
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogIdentityEntry(identity)))
	}

	accountID := identity.AccountID
	identityID := identity.IdentityID
	identitySourceID := identity.IdentitySourceID
	kind := identity.Kind
	identityName := identity.Name
	var result sql.Result
	var err error
	if isCreate {
		identityID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO identities (account_id, identity_id, identity_source_id, kind, name) VALUES (?, ?, ?, ?, ?)", accountID, identityID, identitySourceID, kind, identityName)
	} else {
		result, err = tx.Exec("UPDATE identities SET kind = ? and name = ? WHERE account_id = ? and identity_id = ?", kind, identityName, accountID, identityID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "account id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s identity - operation '%s-identity' encountered an issue (%s).", action, action, LogIdentityEntry(identity)), err, params)
	}

	var dbIdentity Identity
	err = tx.QueryRow("SELECT account_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE account_id = ? and identity_id = ?", accountID, identityID).Scan(
		&dbIdentity.AccountID,
		&dbIdentity.IdentityID,
		&dbIdentity.CreatedAt,
		&dbIdentity.UpdatedAt,
		&dbIdentity.IdentitySourceID,
		&dbIdentity.Kind,
		&dbIdentity.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identity - operation 'retrieve-created-identity' encountered an issue (%s).", LogIdentityEntry(identity)), err)
	}
	return &dbIdentity, nil
}

// DeleteIdentity deletes an identity.
func (r *Repo) DeleteIdentity(tx *sql.Tx, accountID int64, identityID string) (*Identity, error) {
	if err := azivalidators.ValidateAccountID("identity", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageIdentityInvalidAccountID, accountID))
	}
	if err := azivalidators.ValidateUUID("identity", identityID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - identity id is not valid (id: %s).", identityID))
	}
	var dbIdentity Identity
	err := tx.QueryRow("SELECT account_id, identity_id, created_at, updated_at, identity_source_id, kind, name FROM identities WHERE account_id = ? and identity_id = ?", accountID, identityID).Scan(
		&dbIdentity.AccountID,
		&dbIdentity.IdentityID,
		&dbIdentity.CreatedAt,
		&dbIdentity.UpdatedAt,
		&dbIdentity.IdentitySourceID,
		&dbIdentity.Kind,
		&dbIdentity.Name,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - identity id is not valid (id: %s).", identityID), err)
	}
	res, err := tx.Exec("DELETE FROM identities WHERE account_id = ? and identity_id = ?", accountID, identityID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity - operation 'delete-identity' encountered an issue (id: %s).", identityID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete identity - operation 'delete-identity' could not find the identity (id: %s).", identityID), err)
	}
	return &dbIdentity, nil
}

// FetchIdentities retrieves identities.
func (r *Repo) FetchIdentities(db *sqlx.DB, page int32, pageSize int32, accountID int64, filterID *string, filterName *string) ([]Identity, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid.", page, pageSize))
	}
	if err := azivalidators.ValidateAccountID("identity", accountID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageIdentityInvalidAccountID, accountID))
	}

	var dbIdentities []Identity

	baseQuery := "SELECT * FROM identities"
	var conditions []string
	var args []interface{}

	conditions = append(conditions, "account_id = ?")
	args = append(args, accountID)

	if filterID != nil {
		identityID := *filterID
		if err := azivalidators.ValidateUUID("identity", identityID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - identity id is not valid (id: %s).", identityID))
		}
		conditions = append(conditions, "identity_id = ?")
		args = append(args, identityID)
	}

	if filterName != nil {
		identityName := *filterName
		if err := azivalidators.ValidateName("identity", identityName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - identity name is not valid (name: %s).", identityName))
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
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve identities - operation 'retrieve-identities' encountered an issue with parameters %v.", args), err)
	}

	return dbIdentities, nil
}
