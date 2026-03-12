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

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/transport/models/zap"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// CreateZone creates a new zone.
func (s SQLiteCentralStorageZAP) CreateZone(ctx context.Context, zone *zap.Zone) (*zap.Zone, error) {
	if zone == nil {
		return nil, fmt.Errorf("storage: invalid client input - zone is nil: %w", azstorage.ErrInvalidInput)
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
	}
	dbInZone := &azrepos.Zone{
		ZoneID: zone.ZoneID,
		Name:   zone.Name,
	}
	dbOutZone, err := s.sqlRepo.UpsertZone(ctx, tx, true, dbInZone)
	if s.config.EnabledDefaultCreation() {
		if err == nil {
			ledger := &azrepos.Ledger{
				ZoneID: dbOutZone.ZoneID,
				Name:   LedgerDefaultName,
			}
			_, err = s.sqlRepo.UpsertLedger(ctx, tx, true, ledger)
		}
	}
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
	}
	return mapZoneToAgentZone(dbOutZone)
}

// UpdateZone updates a zone.
func (s SQLiteCentralStorageZAP) UpdateZone(ctx context.Context, zone *zap.Zone) (*zap.Zone, error) {
	if zone == nil {
		return nil, fmt.Errorf("storage: invalid client input - zone is nil: %w", azstorage.ErrInvalidInput)
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
	}
	dbInZone := &azrepos.Zone{
		ZoneID: zone.ZoneID,
		Name:   zone.Name,
	}
	dbOutzone, err := s.sqlRepo.UpsertZone(ctx, tx, false, dbInZone)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
	}
	return mapZoneToAgentZone(dbOutzone)
}

// DeleteZone deletes a zone.
func (s SQLiteCentralStorageZAP) DeleteZone(ctx context.Context, zoneID int64) (*zap.Zone, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotBeginTransaction, err)
	}
	dbOutzone, err := s.sqlRepo.DeleteZone(ctx, tx, zoneID)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotCommitTransaction, err)
	}
	return mapZoneToAgentZone(dbOutzone)
}

// FetchZones returns all zones.
func (s SQLiteCentralStorageZAP) FetchZones(ctx context.Context, page int32, pageSize int32, fields map[string]any) ([]zap.Zone, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.DataFetchMaxPageSize() {
		return nil, fmt.Errorf("storage: invalid client input - page number %d or page size %d is not valid: %w", page, pageSize, azstorage.ErrInvalidInput)
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	var filterID *int64
	if _, ok := fields[zap.FieldZoneZoneID]; ok {
		zoneID, ok := fields[zap.FieldZoneZoneID].(int64)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - zone id is not valid (zone id: %d): %w", zoneID, azstorage.ErrInvalidInput)
		}
		filterID = &zoneID
	}
	var filterName *string
	if _, ok := fields[zap.FieldZoneName]; ok {
		zoneName, ok := fields[zap.FieldZoneName].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid client input - zone name is not valid (zone name: %s): %w", zoneName, azstorage.ErrInvalidInput)
		}
		filterName = &zoneName
	}
	dbZones, err := s.sqlRepo.FetchZones(ctx, db, page, pageSize, filterID, filterName)
	if err != nil {
		return nil, err
	}
	zones := make([]zap.Zone, len(dbZones))
	for i, a := range dbZones {
		zone, err := mapZoneToAgentZone(&a)
		if err != nil {
			return nil, fmt.Errorf("storage: failed to convert zone entity (%s): %w", azrepos.LogZoneEntry(&a), azstorage.ErrInternal)
		}
		zones[i] = *zone
	}
	return zones, nil
}
