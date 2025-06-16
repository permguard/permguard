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
	"errors"
	"fmt"

	"github.com/permguard/permguard/pkg/transport/models/pap"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	LedgerDefaultName = "default"
)

// CreateLedger creates a new ledger.
func (s SQLiteCentralStoragePAP) CreateLedger(ledger *pap.Ledger) (*pap.Ledger, error) {
	if ledger == nil {
		return nil, errors.New("storage: invalid client input - ledger is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	if ledger.Kind == "" {
		ledger.Kind = repos.LedgerTypePolicy
	}
	kind, err := repos.ConvertLedgerKindToID(ledger.Kind)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("storage: invalid client input - ledger kind %s is not valid", ledger.Kind))
	}
	dbInLedger := &repos.Ledger{
		ZoneID: ledger.ZoneID,
		Name:   ledger.Name,
		Kind:   kind,
	}
	dbOutLedger, err := s.sqlRepo.UpsertLedger(tx, true, dbInLedger)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// UpdateLedger updates a ledger.
func (s SQLiteCentralStoragePAP) UpdateLedger(ledger *pap.Ledger) (*pap.Ledger, error) {
	if ledger == nil {
		return nil, errors.New("storage: invalid client input - ledger is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	if ledger.Kind == "" {
		ledger.Kind = repos.LedgerTypePolicy
	}
	kind, err := repos.ConvertLedgerKindToID(ledger.Kind)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("storage: invalid client input - ledger kind %s is not valid", ledger.Kind))
	}
	dbInLedger := &repos.Ledger{
		LedgerID: ledger.LedgerID,
		ZoneID:   ledger.ZoneID,
		Kind:     kind,
		Name:     ledger.Name,
	}
	dbOutLedger, err := s.sqlRepo.UpsertLedger(tx, false, dbInLedger)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// DeleteLedger deletes a ledger.
func (s SQLiteCentralStoragePAP) DeleteLedger(zoneID int64, ledgerID string) (*pap.Ledger, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutLedger, err := s.sqlRepo.DeleteLedger(tx, zoneID, ledgerID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, repos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// FetchLedgers returns all ledgers.
func (s SQLiteCentralStoragePAP) FetchLedgers(page int32, pageSize int32, zoneID int64, fields map[string]any) ([]pap.Ledger, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.DataFetchMaxPageSize() {
		return nil, fmt.Errorf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize)
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *string
	if _, ok := fields[pap.FieldLedgerLedgerID]; ok {
		ledgerID, ok := fields[pap.FieldLedgerLedgerID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - ledger id is not valid (ledger id: %s)", ledgerID)
		}
		filterID = &ledgerID
	}
	var filterName *string
	if _, ok := fields[pap.FieldLedgerName]; ok {
		ledgerName, ok := fields[pap.FieldLedgerName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - ledger name is not valid (ledger name: %s)", ledgerName)
		}
		filterName = &ledgerName
	}
	dbLedgers, err := s.sqlRepo.FetchLedgers(db, page, pageSize, zoneID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	ledgers := make([]pap.Ledger, len(dbLedgers))
	for i, a := range dbLedgers {
		ledger, err := mapLedgerToAgentLedger(&a)
		if err != nil {
			return nil, fmt.Errorf("storage: failed to convert ledger entity (%s)", repos.LogLedgerEntry(&a))
		}
		ledgers[i] = *ledger
	}
	return ledgers, nil
}
