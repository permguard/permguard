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
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/agents/telemetry"
	"github.com/permguard/permguard/pkg/transport/models/pap"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

const (
	// LedgerDefaultName is the default name for a ledger.
	LedgerDefaultName = "default"
)

// CreateLedger creates a new ledger.
func (s SQLiteCentralStoragePAP) CreateLedger(ctx context.Context, ledger *pap.Ledger) (_ *pap.Ledger, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.CreateLedger")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.LedgerCreateTotal.Add(ctx, 1, telemetry.StatusAttr(st))
		telemetry.LedgerOpDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.OpAttr("create"), telemetry.StatusAttr(st))
	}()
	if ledger == nil {
		return nil, fmt.Errorf("storage: invalid client input - ledger is nil: %w", azstorage.ErrInvalidInput)
	}
	span.SetAttributes(attribute.Int64("zone_id", ledger.ZoneID), attribute.String("ledger_name", ledger.Name))
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
	}
	if ledger.Kind == "" {
		ledger.Kind = azrepos.LedgerTypePolicy
	}
	kind, err := azrepos.ConvertLedgerKindToID(ledger.Kind)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid client input - ledger kind %s is not valid: %w", ledger.Kind, azstorage.ErrInvalidInput)
	}
	dbInLedger := &azrepos.Ledger{
		ZoneID: ledger.ZoneID,
		Name:   ledger.Name,
		Kind:   kind,
	}
	dbOutLedger, err := s.sqlRepo.UpsertLedger(ctx, tx, true, dbInLedger)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// UpdateLedger updates a ledger.
func (s SQLiteCentralStoragePAP) UpdateLedger(ctx context.Context, ledger *pap.Ledger) (_ *pap.Ledger, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.UpdateLedger")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.LedgerUpdateTotal.Add(ctx, 1, telemetry.StatusAttr(st))
		telemetry.LedgerOpDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.OpAttr("update"), telemetry.StatusAttr(st))
	}()
	if ledger == nil {
		return nil, fmt.Errorf("storage: invalid client input - ledger is nil: %w", azstorage.ErrInvalidInput)
	}
	span.SetAttributes(attribute.Int64("zone_id", ledger.ZoneID), attribute.String("ledger_id", ledger.LedgerID))
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
	}
	if ledger.Kind == "" {
		ledger.Kind = azrepos.LedgerTypePolicy
	}
	kind, err := azrepos.ConvertLedgerKindToID(ledger.Kind)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid client input - ledger kind %s is not valid: %w", ledger.Kind, azstorage.ErrInvalidInput)
	}
	dbInLedger := &azrepos.Ledger{
		LedgerID: ledger.LedgerID,
		ZoneID:   ledger.ZoneID,
		Kind:     kind,
		Name:     ledger.Name,
	}
	dbOutLedger, err := s.sqlRepo.UpsertLedger(ctx, tx, false, dbInLedger)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// DeleteLedger deletes a ledger.
func (s SQLiteCentralStoragePAP) DeleteLedger(ctx context.Context, zoneID int64, ledgerID string) (_ *pap.Ledger, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.DeleteLedger")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.LedgerDeleteTotal.Add(ctx, 1, telemetry.StatusAttr(st))
		telemetry.LedgerOpDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.OpAttr("delete"), telemetry.StatusAttr(st))
	}()
	span.SetAttributes(attribute.Int64("zone_id", zoneID), attribute.String("ledger_id", ledgerID))
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
	}
	dbOutLedger, err := s.sqlRepo.DeleteLedger(ctx, tx, zoneID, ledgerID)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
	}
	return mapLedgerToAgentLedger(dbOutLedger)
}

// FetchLedgers returns all ledgers.
func (s SQLiteCentralStoragePAP) FetchLedgers(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) (_ []pap.Ledger, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.FetchLedgers")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.LedgerFetchTotal.Add(ctx, 1, telemetry.StatusAttr(st))
		telemetry.LedgerOpDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.OpAttr("fetch"), telemetry.StatusAttr(st))
	}()
	span.SetAttributes(attribute.Int64("zone_id", zoneID))
	if page <= 0 || pageSize <= 0 || pageSize > s.config.DataFetchMaxPageSize() {
		return nil, fmt.Errorf("storage: invalid client input - page number %d or page size %d is not valid: %w", page, pageSize, azstorage.ErrInvalidInput)
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	var filterID *string
	if _, ok := fields[pap.FieldLedgerLedgerID]; ok {
		ledgerID, ok := fields[pap.FieldLedgerLedgerID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - ledger id is not valid (ledger id: %s): %w", ledgerID, azstorage.ErrInvalidInput)
		}
		filterID = &ledgerID
	}
	var filterName *string
	if _, ok := fields[pap.FieldLedgerName]; ok {
		ledgerName, ok := fields[pap.FieldLedgerName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - ledger name is not valid (ledger name: %s): %w", ledgerName, azstorage.ErrInvalidInput)
		}
		filterName = &ledgerName
	}
	dbLedgers, err := s.sqlRepo.FetchLedgers(ctx, db, page, pageSize, zoneID, filterID, filterName)
	if err != nil {
		return nil, err
	}
	ledgers := make([]pap.Ledger, len(dbLedgers))
	for i, a := range dbLedgers {
		ledger, err := mapLedgerToAgentLedger(&a)
		if err != nil {
			return nil, fmt.Errorf("storage: failed to convert ledger entity (%s): %w", azrepos.LogLedgerEntry(&a), azstorage.ErrInternal)
		}
		ledgers[i] = *ledger
	}
	span.SetAttributes(attribute.Int("result_count", len(ledgers)))
	return ledgers, nil
}
