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

package centralstorage

import (
	"fmt"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	LedgerDefaultName = "default"
)

// CreateLedger creates a new ledger.
func (s SQLiteCentralStoragePAP) CreateLedger(ledger *azmodels.Ledger) (*azmodels.Ledger, error) {
	if ledger == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - ledger is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInLedger := &azirepos.Ledger{
		ApplicationID: ledger.ApplicationID,
		Name:          ledger.Name,
	}
	dbOutLedger, err := s.sqlRepo.UpsertLedger(tx, true, dbInLedger)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// UpdateLedger updates a ledger.
func (s SQLiteCentralStoragePAP) UpdateLedger(ledger *azmodels.Ledger) (*azmodels.Ledger, error) {
	if ledger == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid client input - ledger is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInLedger := &azirepos.Ledger{
		LedgerID:      ledger.LedgerID,
		ApplicationID: ledger.ApplicationID,
		Kind:          1,
		Name:          ledger.Name,
	}
	dbOutLedger, err := s.sqlRepo.UpsertLedger(tx, false, dbInLedger)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// DeleteLedger deletes a ledger.
func (s SQLiteCentralStoragePAP) DeleteLedger(applicationID int64, ledgerID string) (*azmodels.Ledger, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutLedger, err := s.sqlRepo.DeleteLedger(tx, applicationID, ledgerID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// FetchLedgers returns all ledgers.
func (s SQLiteCentralStoragePAP) FetchLedgers(page int32, pageSize int32, applicationID int64, fields map[string]any) ([]azmodels.Ledger, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientPagination, fmt.Sprintf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[azmodels.FieldLedgerLedgerID]; ok {
		ledgerID, ok := fields[azmodels.FieldLedgerLedgerID].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - ledger id is not valid (ledger id: %s)", ledgerID))
		}
		filterID = &ledgerID
	}
	var filterName *string
	if _, ok := fields[azmodels.FieldLedgerName]; ok {
		ledgerName, ok := fields[azmodels.FieldLedgerName].(string)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, fmt.Sprintf("storage: invalid client input - ledger name is not valid (ledger name: %s)", ledgerName))
		}
		filterName = &ledgerName
	}
	dbLedgers, err := s.sqlRepo.FetchLedgers(db, page, pageSize, applicationID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	ledgers := make([]azmodels.Ledger, len(dbLedgers))
	for i, a := range dbLedgers {
		ledger, err := mapLedgerToAgentLedger(&a)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrStorageEntityMapping, fmt.Sprintf("storage: failed to convert ledger entity (%s)", azirepos.LogLedgerEntry(&a)))
		}
		ledgers[i] = *ledger
	}
	return ledgers, nil
}
