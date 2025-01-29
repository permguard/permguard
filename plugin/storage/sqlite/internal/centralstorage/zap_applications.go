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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelzap "github.com/permguard/permguard/pkg/transport/models/zap"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// CreateZone creates a new zone.
func (s SQLiteCentralStorageZAP) CreateZone(zone *azmodelzap.Zone) (*azmodelzap.Zone, error) {
	if zone == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, " invalid client input - zone is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInZone := &azirepos.Zone{
		ZoneID: zone.ZoneID,
		Name:   zone.Name,
	}
	dbOutZone, err := s.sqlRepo.UpsertZone(tx, true, dbInZone)
	if s.config.GetEnabledDefaultCreation() {
		if err == nil {
			tenant := &azirepos.Tenant{
				ZoneID: dbOutZone.ZoneID,
				Name:   TenantDefaultName,
			}
			_, err = s.sqlRepo.UpsertTenant(tx, true, tenant)
		}
		if err == nil {
			identitySource := &azirepos.IdentitySource{
				ZoneID: dbOutZone.ZoneID,
				Name:   IdentitySourceDefaultName,
			}
			_, err = s.sqlRepo.UpsertIdentitySource(tx, true, identitySource)
		}
		if err == nil {
			ledger := &azirepos.Ledger{
				ZoneID: dbOutZone.ZoneID,
				Name:   LedgerDefaultName,
			}
			_, err = s.sqlRepo.UpsertLedger(tx, true, ledger)
		}
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapZoneToAgentZone(dbOutZone)
}

// UpdateZone updates a zone.
func (s SQLiteCentralStorageZAP) UpdateZone(zone *azmodelzap.Zone) (*azmodelzap.Zone, error) {
	if zone == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, " invalid client input - zone is nil")
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbInZone := &azirepos.Zone{
		ZoneID: zone.ZoneID,
		Name:   zone.Name,
	}
	dbOutzone, err := s.sqlRepo.UpsertZone(tx, false, dbInZone)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapZoneToAgentZone(dbOutzone)
}

// DeleteZone deletes a zone.
func (s SQLiteCentralStorageZAP) DeleteZone(zoneID int64) (*azmodelzap.Zone, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	dbOutzone, err := s.sqlRepo.DeleteZone(tx, zoneID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
	}
	return mapZoneToAgentZone(dbOutzone)
}

// FetchZones returns all zones.
func (s SQLiteCentralStorageZAP) FetchZones(page int32, pageSize int32, fields map[string]any) ([]azmodelzap.Zone, error) {
	if page <= 0 || pageSize <= 0 || pageSize > s.config.GetDataFetchMaxPageSize() {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientPagination, fmt.Sprintf(" invalid client input - page number %d or page size %d is not valid", page, pageSize))
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, err
	}
	var filterID *int64
	if _, ok := fields[azmodelzap.FieldZoneZoneID]; ok {
		zoneID, ok := fields[azmodelzap.FieldZoneZoneID].(int64)
		if !ok {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf(" invalid client input - zone id is not valid (zone id: %d)", zoneID))
		}
		filterID = &zoneID
	}
	var filterName *string
	if _, ok := fields[azmodelzap.FieldZoneName]; ok {
		zoneName, ok := fields[azmodelzap.FieldZoneName].(string)
		if !ok {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientParameter, fmt.Sprintf(" invalid client input - zone name is not valid (zone name: %s)", zoneName))
		}
		filterName = &zoneName
	}
	dbZones, err := s.sqlRepo.FetchZones(db, page, pageSize, filterID, filterName)
	if err != nil {
		return nil, err
	}
	zones := make([]azmodelzap.Zone, len(dbZones))
	for i, a := range dbZones {
		zone, err := mapZoneToAgentZone(&a)
		if err != nil {
			return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageEntityMapping, fmt.Sprintf(" failed to convert zone entity (%s)", azirepos.LogZoneEntry(&a)))
		}
		zones[i] = *zone
	}
	return zones, nil
}
