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
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // SQLite driver

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/core/validators"
)

// Ledger type constants.
const (
	// errorMessageLedgerInvalidZoneID is the error message ledger invalid zone id.
	errorMessageLedgerInvalidZoneID = "storage: invalid client input - zone id is not valid (id: %d)"
)

// Ledger type constants.
const (
	LedgerType       = "ledger"
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
		return 0, fmt.Errorf("invalid client input - ledger kind %s is not valid: %w", kind, azstorage.ErrInvalidInput)
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
func (r *Repository) UpsertLedger(ctx context.Context, tx *sql.Tx, isCreate bool, ledger *Ledger) (*Ledger, error) {
	if ledger == nil {
		return nil, fmt.Errorf("storage: invalid client input - ledger data is missing or malformed (%s): %w", LogLedgerEntry(ledger), azstorage.ErrInvalidInput)
	}
	if err := validators.ValidateCodeID(LedgerType, ledger.ZoneID); err != nil {
		return nil, fmt.Errorf(errorMessageLedgerInvalidZoneID+": %w", ledger.ZoneID, azstorage.ErrInvalidInput)
	}
	if !isCreate && validators.ValidateUUID(LedgerType, ledger.LedgerID) != nil {
		return nil, fmt.Errorf("storage: invalid client input - ledger id is not valid (%s): %w", LogLedgerEntry(ledger), azstorage.ErrInvalidInput)
	}
	if err := validators.ValidateName(LedgerType, ledger.Name); err != nil {
		return nil, fmt.Errorf("invalid client input - ledger name is not valid (%s): %w", LogLedgerEntry(ledger), azstorage.ErrInvalidInput)
	}

	zoneID := ledger.ZoneID
	ledgerID := ledger.LedgerID
	ledgerName := ledger.Name
	ledgerKind := ledger.Kind
	var result sql.Result
	var err error
	if isCreate {
		ledgerID = GenerateUUID()
		result, err = tx.ExecContext(ctx, "INSERT INTO ledgers (zone_id, ledger_id, kind, name) VALUES (?, ?, ?, ?)", zoneID, ledgerID, ledgerKind, ledgerName)
	} else {
		result, err = tx.ExecContext(ctx, "UPDATE ledgers SET name = ? WHERE zone_id = ? and ledger_id = ?", ledgerName, zoneID, ledgerID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		params := map[string]string{WrapSqliteParamForeignKey: "zone id"}
		return nil, WrapSqliteErrorWithParams(fmt.Sprintf("failed to %s ledger - operation '%s-ledger' encountered an issue (%s)", action, action, LogLedgerEntry(ledger)), err, params)
	}

	var dbLedger Ledger
	err = tx.QueryRowContext(ctx, "SELECT zone_id, ledger_id, created_at, updated_at, kind, name, ref, txid FROM ledgers WHERE zone_id = ? and ledger_id = ?", zoneID, ledgerID).Scan(
		&dbLedger.ZoneID,
		&dbLedger.LedgerID,
		&dbLedger.CreatedAt,
		&dbLedger.UpdatedAt,
		&dbLedger.Kind,
		&dbLedger.Name,
		&dbLedger.Ref,
		&dbLedger.TxID,
	)
	if err != nil {
		return nil, WrapSqliteError(fmt.Sprintf("failed to retrieve ledger - operation 'retrieve-created-ledger' encountered an issue (%s)", LogLedgerEntry(ledger)), err)
	}
	return &dbLedger, nil
}

// UpdateLedgerRef updates the ref and txid of a ledger.
func (r *Repository) UpdateLedgerRef(ctx context.Context, tx *sql.Tx, zoneID int64, ledgerID, currentRef, newRef, txid string) error {
	if err := validators.ValidateCodeID(LedgerType, zoneID); err != nil {
		return fmt.Errorf(errorMessageLedgerInvalidZoneID+": %w", zoneID, azstorage.ErrInvalidInput)
	}
	if err := validators.ValidateUUID(LedgerType, ledgerID); err != nil {
		return fmt.Errorf("storage: invalid client input - ledger id is not valid (id: %s): %w", ledgerID, azstorage.ErrInvalidInput)
	}
	if err := validators.ValidateOID(LedgerType, currentRef); err != nil {
		return fmt.Errorf("storage: invalid client input - current ref is not valid (ref: %s): %w", currentRef, azstorage.ErrInvalidInput)
	}
	if err := validators.ValidateOID(LedgerType, newRef); err != nil {
		return fmt.Errorf("storage: invalid client input - new ref is not valid (ref: %s): %w", newRef, azstorage.ErrInvalidInput)
	}

	var dbCurrentRef string
	err := tx.QueryRowContext(ctx, "SELECT ref FROM ledgers WHERE zone_id = ? AND ledger_id = ?", zoneID, ledgerID).Scan(&dbCurrentRef)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("storage: ledger not found (zone_id: %d, ledger_id: %s): %w", zoneID, ledgerID, azstorage.ErrNotFound)
		}
		return WrapSqliteError("failed to retrieve current ref for ledger", err)
	}

	if dbCurrentRef != currentRef {
		return fmt.Errorf("current ref mismatch (expected: %s, got: %s): %w", dbCurrentRef, currentRef, azstorage.ErrConflict)
	}

	result, err := tx.ExecContext(ctx, "UPDATE ledgers SET ref = ?, txid = ? WHERE zone_id = ? AND ledger_id = ?", newRef, txid, zoneID, ledgerID)
	if err != nil {
		return WrapSqliteError("failed to update ledger ref", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return WrapSqliteError("failed to get rows affected for update ref", err)
	}
	if rows != 1 {
		return fmt.Errorf("update failed, no rows affected (zone_id: %d, ledger_id: %s): %w", zoneID, ledgerID, azstorage.ErrNotFound)
	}
	return nil
}

// DeleteLedger deletes a ledger.
func (r *Repository) DeleteLedger(ctx context.Context, tx *sql.Tx, zoneID int64, ledgerID string) (*Ledger, error) {
	if err := validators.ValidateCodeID(LedgerType, zoneID); err != nil {
		return nil, fmt.Errorf(errorMessageLedgerInvalidZoneID+": %w", zoneID, azstorage.ErrInvalidInput)
	}
	if err := validators.ValidateUUID(LedgerType, ledgerID); err != nil {
		return nil, fmt.Errorf("storage: invalid client input - ledger id is not valid (id: %s): %w", ledgerID, azstorage.ErrInvalidInput)
	}

	var dbLedger Ledger
	err := tx.QueryRowContext(ctx, "SELECT zone_id, ledger_id, created_at, updated_at, kind, name, ref, txid FROM ledgers WHERE zone_id = ? and ledger_id = ?", zoneID, ledgerID).Scan(
		&dbLedger.ZoneID,
		&dbLedger.LedgerID,
		&dbLedger.CreatedAt,
		&dbLedger.UpdatedAt,
		&dbLedger.Kind,
		&dbLedger.Name,
		&dbLedger.Ref,
		&dbLedger.TxID,
	)
	if err != nil {
		return nil, WrapSqliteError(fmt.Sprintf("invalid client input - ledger id is not valid (id: %s)", ledgerID), err)
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM ledgers WHERE zone_id = ? and ledger_id = ?", zoneID, ledgerID)
	if err != nil || res == nil {
		return nil, WrapSqliteError(fmt.Sprintf("failed to delete ledger - operation 'delete-ledger' encountered an issue (id: %s)", ledgerID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, WrapSqliteError(fmt.Sprintf("failed to delete ledger - operation 'delete-ledger' could not find the ledger (id: %s)", ledgerID), err)
	}
	return &dbLedger, nil
}

// FetchLedgers retrieves ledgers.
func (r *Repository) FetchLedgers(ctx context.Context, db *sqlx.DB, page int32, pageSize int32, zoneID int64, filterID *string, filterName *string) ([]Ledger, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, fmt.Errorf("storage: invalid client input - page number %d or page size %d is not valid: %w", page, pageSize, azstorage.ErrInvalidInput)
	}
	if err := validators.ValidateCodeID(LedgerType, zoneID); err != nil {
		return nil, fmt.Errorf(errorMessageLedgerInvalidZoneID+": %w", zoneID, azstorage.ErrInvalidInput)
	}

	var dbLedgers []Ledger

	baseQuery := "SELECT * FROM ledgers"
	var conditions []string
	var args []any

	conditions = append(conditions, "zone_id = ?")
	args = append(args, zoneID)

	if filterID != nil {
		ledgerID := *filterID
		if err := validators.ValidateUUID(LedgerType, ledgerID); err != nil {
			return nil, fmt.Errorf("storage: invalid client input - ledger id is not valid (id: %s): %w", ledgerID, azstorage.ErrInvalidInput)
		}
		conditions = append(conditions, "ledger_id = ?")
		args = append(args, ledgerID)
	}

	if filterName != nil {
		ledgerName := *filterName
		if err := validators.ValidateName(LedgerType, ledgerName); err != nil {
			return nil, fmt.Errorf("storage: invalid client input - ledger name is not valid (name: %s): %w", ledgerName, azstorage.ErrInvalidInput)
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

	err := db.SelectContext(ctx, &dbLedgers, baseQuery, args...)
	if err != nil {
		return nil, WrapSqliteError(fmt.Sprintf("failed to retrieve ledgers - operation 'retrieve-ledgers' encountered an issue with parameters %v", args), err)
	}

	return dbLedgers, nil
}
