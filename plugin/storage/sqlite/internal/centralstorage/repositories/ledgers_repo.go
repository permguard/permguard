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
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// errorMessageLedgerInvalidApplicationID is the error message ledger invalid application id.
	errorMessageLedgerInvalidApplicationID = "storage: invalid client input - application id is not valid (id: %d)"
)

const (
	LedgerTypePolicy = "policy"
)

// ledgersMap is a map of ledger kinds to IDs.
var ledgersMap = map[string]int16{
	LedgerTypePolicy: 1,
}

// ConvertLedgerKindToID converts an ledger kind to an ID.
func ConvertLedgerKindToID(kind string) (int16, error) {
	cKey := strings.ToLower(kind)
	value, ok := ledgersMap[cKey]
	if !ok {
		return 0, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - ledger kind %s is not valid", kind))
	}
	return value, nil
}

// ConvertLedgerKindToString converts an ledger kind to a string.
func ConvertLedgerKindToString(id int16) (string, error) {
	for k, v := range ledgersMap {
		if v == id {
			return k, nil
		}
	}
	return "", nil
}

// UpsertLedger creates or updates a ledger.
func (r *Repository) UpsertLedger(tx *sql.Tx, isCreate bool, ledger *Ledger) (*Ledger, error) {
	if ledger == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - ledger data is missing or malformed (%s)", LogLedgerEntry(ledger)))
	}
	if err := azvalidators.ValidateCodeID("ledger", ledger.ApplicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageLedgerInvalidApplicationID, ledger.ApplicationID))
	}
	if !isCreate && azvalidators.ValidateUUID("ledger", ledger.LedgerID) != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - ledger id is not valid (%s)", LogLedgerEntry(ledger)))
	}
	if err := azvalidators.ValidateName("ledger", ledger.Name); err != nil {
		errorMessage := "storage: invalid client input - ledger name is not valid (%s)"
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessage, LogLedgerEntry(ledger)))
	}

	applicationID := ledger.ApplicationID
	ledgerID := ledger.LedgerID
	ledgerName := ledger.Name
	ledgerKind := ledger.Kind
	var result sql.Result
	var err error
	if isCreate {
		ledgerID = GenerateUUID()
		result, err = tx.Exec("INSERT INTO ledgers (application_id, ledger_id, kind, name) VALUES (?, ?, ?, ?)", applicationID, ledgerID, ledgerKind, ledgerName)
	} else {
		result, err = tx.Exec("UPDATE ledgers SET name = ? WHERE application_id = ? and ledger_id = ?", ledgerName, applicationID, ledgerID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqlite3ParamForeignKey: "application id"}
		return nil, WrapSqlite3ErrorWithParams(fmt.Sprintf("failed to %s ledger - operation '%s-ledger' encountered an issue (%s)", action, action, LogLedgerEntry(ledger)), err, params)
	}

	var dbLedger Ledger
	err = tx.QueryRow("SELECT application_id, ledger_id, created_at, updated_at, kind, name, ref FROM ledgers WHERE application_id = ? and ledger_id = ?", applicationID, ledgerID).Scan(
		&dbLedger.ApplicationID,
		&dbLedger.LedgerID,
		&dbLedger.CreatedAt,
		&dbLedger.UpdatedAt,
		&dbLedger.Kind,
		&dbLedger.Name,
		&dbLedger.Ref,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve ledger - operation 'retrieve-created-ledger' encountered an issue (%s)", LogLedgerEntry(ledger)), err)
	}
	return &dbLedger, nil
}

// UpdateLedgerRef updates the ref of a ledger.
func (r *Repository) UpdateLedgerRef(tx *sql.Tx, applicationID int64, ledgerID, currentRef, newRef string) error {
	if err := azvalidators.ValidateCodeID("ledger", applicationID); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageLedgerInvalidApplicationID, applicationID))
	}
	if err := azvalidators.ValidateUUID("ledger", ledgerID); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - ledger id is not valid (id: %s)", ledgerID))
	}
	if err := azvalidators.ValidateSHA256("ledger", currentRef); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - current ref is not valid (ref: %s)", currentRef))
	}
	if err := azvalidators.ValidateSHA256("ledger", newRef); err != nil {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - new ref is not valid (ref: %s)", newRef))
	}

	var dbCurrentRef string
	err := tx.QueryRow("SELECT ref FROM ledgers WHERE application_id = ? AND ledger_id = ?", applicationID, ledgerID).Scan(&dbCurrentRef)
	if err != nil {
		if err == sql.ErrNoRows {
			return azerrors.WrapSystemError(azerrors.ErrClientNotFound, fmt.Sprintf("ledger not found (application_id: %d, ledger_id: %s)", applicationID, ledgerID))
		}
		return WrapSqlite3Error("failed to retrieve current ref for ledger", err)
	}

	if dbCurrentRef != currentRef {
		return azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("current ref mismatch (expected: %s, got: %s)", dbCurrentRef, currentRef))
	}

	result, err := tx.Exec("UPDATE ledgers SET ref = ? WHERE application_id = ? AND ledger_id = ?", newRef, applicationID, ledgerID)
	if err != nil {
		return WrapSqlite3Error("failed to update ledger ref", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return WrapSqlite3Error("failed to get rows affected for update ref", err)
	}
	if rows != 1 {
		return azerrors.WrapSystemError(azerrors.ErrClientUpdateConflict, fmt.Sprintf("update failed, no rows affected (application_id: %d, ledger_id: %s)", applicationID, ledgerID))
	}
	return nil
}

// DeleteLedger deletes a ledger.
func (r *Repository) DeleteLedger(tx *sql.Tx, applicationID int64, ledgerID string) (*Ledger, error) {
	if err := azvalidators.ValidateCodeID("ledger", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf(errorMessageLedgerInvalidApplicationID, applicationID))
	}
	if err := azvalidators.ValidateUUID("ledger", ledgerID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - ledger id is not valid (id: %s)", ledgerID))
	}

	var dbLedger Ledger
	err := tx.QueryRow("SELECT application_id, ledger_id, created_at, updated_at, kind, name, ref FROM ledgers WHERE application_id = ? and ledger_id = ?", applicationID, ledgerID).Scan(
		&dbLedger.ApplicationID,
		&dbLedger.LedgerID,
		&dbLedger.CreatedAt,
		&dbLedger.UpdatedAt,
		&dbLedger.Kind,
		&dbLedger.Name,
		&dbLedger.Ref,
	)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("invalid client input - ledger id is not valid (id: %s)", ledgerID), err)
	}
	res, err := tx.Exec("DELETE FROM ledgers WHERE application_id = ? and ledger_id = ?", applicationID, ledgerID)
	if err != nil || res == nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete ledger - operation 'delete-ledger' encountered an issue (id: %s)", ledgerID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to delete ledger - operation 'delete-ledger' could not find the ledger (id: %s)", ledgerID), err)
	}
	return &dbLedger, nil
}

// FetchLedgers retrieves ledgers.
func (r *Repository) FetchLedgers(db *sqlx.DB, page int32, pageSize int32, applicationID int64, filterID *string, filterName *string) ([]Ledger, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	if err := azvalidators.ValidateCodeID("ledger", applicationID); err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf(errorMessageLedgerInvalidApplicationID, applicationID))
	}

	var dbLedgers []Ledger

	baseQuery := "SELECT * FROM ledgers"
	var conditions []string
	var args []any

	conditions = append(conditions, "application_id = ?")
	args = append(args, applicationID)

	if filterID != nil {
		ledgerID := *filterID
		if err := azvalidators.ValidateUUID("ledger", ledgerID); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientID, fmt.Sprintf("storage: invalid client input - ledger id is not valid (id: %s)", ledgerID))
		}
		conditions = append(conditions, "ledger_id = ?")
		args = append(args, ledgerID)
	}

	if filterName != nil {
		ledgerName := *filterName
		if err := azvalidators.ValidateName("ledger", ledgerName); err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientName, fmt.Sprintf("storage: invalid client input - ledger name is not valid (name: %s)", ledgerName))
		}
		ledgerName = "%" + ledgerName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, ledgerName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY ledger_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbLedgers, baseQuery, args...)
	if err != nil {
		return nil, WrapSqlite3Error(fmt.Sprintf("failed to retrieve ledgers - operation 'retrieve-ledgers' encountered an issue with parameters %v", args), err)
	}

	return dbLedgers, nil
}
