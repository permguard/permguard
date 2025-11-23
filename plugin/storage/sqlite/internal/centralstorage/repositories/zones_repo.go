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
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"

	"github.com/permguard/permguard/pkg/core/validators"
)

// GenerateZoneID generates a random zone id.
func GenerateZoneID() int64 {
	const base = 100000000000
	const maxRange = 900000000000
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Int63n(maxRange)
	zoneID := base + randomNumber
	return zoneID
}

// UpsertZone creates or updates a zone.
func (r *Repository) UpsertZone(tx *sql.Tx, isCreate bool, zone *Zone) (*Zone, error) {
	if zone == nil {
		return nil, fmt.Errorf("storage: invalid client input - zone data is missing or malformed (%s)", LogZoneEntry(zone))
	}
	if !isCreate && validators.ValidateCodeID("zone", zone.ZoneID) != nil {
		return nil, fmt.Errorf("storage: invalid client input - zone id is not valid (%s)", LogZoneEntry(zone))
	}
	if err := validators.ValidateName("zone", zone.Name); err != nil {
		errorMessage := "invalid client input - zone name is not valid (%s)"
		return nil, errors.Join(fmt.Errorf(errorMessage, LogZoneEntry(zone)), err)
	}

	zoneID := zone.ZoneID
	zoneName := zone.Name
	var result sql.Result
	var err error
	if isCreate {
		zoneID = GenerateZoneID()
		result, err = tx.Exec("INSERT INTO zones (zone_id, name) VALUES (?, ?)", zoneID, zoneName)
	} else {
		result, err = tx.Exec("UPDATE zones SET name = ? WHERE zone_id = ?", zoneName, zoneID)
	}
	if err != nil || result == nil {
		action := "update"
		if isCreate {
			action = "create"
		}
		return nil, errors.Join(fmt.Errorf("storage: failed to %s zone - operation '%s-zone' encountered an issue (%s)", action, action, LogZoneEntry(zone)), err)
	}

	var dbZone Zone
	err = tx.QueryRow("SELECT zone_id, created_at, updated_at, name FROM zones WHERE zone_id = ?", zoneID).Scan(
		&dbZone.ZoneID,
		&dbZone.CreatedAt,
		&dbZone.UpdatedAt,
		&dbZone.Name,
	)
	if err != nil {
		return nil, WrapSqliteError(fmt.Sprintf("storage: failed to retrieve zone - operation 'retrieve-created-zone' encountered an issue (%s)", LogZoneEntry(zone)), err)
	}
	return &dbZone, nil
}

// DeleteZone deletes a zone.
func (r *Repository) DeleteZone(tx *sql.Tx, zoneID int64) (*Zone, error) {
	if err := validators.ValidateCodeID("zone", zoneID); err != nil {
		return nil, errors.Join(fmt.Errorf("storage: invalid client input - zone id is not valid (id: %d)", zoneID), err)
	}

	var dbZone Zone
	err := tx.QueryRow("SELECT zone_id, created_at, updated_at, name FROM zones WHERE zone_id = ?", zoneID).Scan(
		&dbZone.ZoneID,
		&dbZone.CreatedAt,
		&dbZone.UpdatedAt,
		&dbZone.Name,
	)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("storage: invalid client input - zone id is not valid (id: %d)", zoneID), err)
	}
	res, err := tx.Exec("DELETE FROM zones WHERE zone_id = ?", zoneID)
	if err != nil || res == nil {
		return nil, errors.Join(fmt.Errorf("storage: failed to delete zone - operation 'delete-zone' encountered an issue (id: %d)", zoneID), err)
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return nil, errors.Join(fmt.Errorf("storage: failed to delete zone - operation 'delete-zone' encountered an issue (id: %d)", zoneID), err)
	}
	return &dbZone, nil
}

// FetchZones retrieves zones.
func (r *Repository) FetchZones(db *sqlx.DB, page int32, pageSize int32, filterID *int64, filterName *string) ([]Zone, error) {
	if page <= 0 || pageSize <= 0 {
		return nil, fmt.Errorf("storage: invalid client input - page number %d or page size %d is not valid", page, pageSize)
	}
	var dbZones []Zone

	baseQuery := "SELECT * FROM zones"
	var conditions []string
	var args []any

	if filterID != nil {
		zoneID := *filterID
		if err := validators.ValidateCodeID("zone", zoneID); err != nil {
			return nil, errors.Join(fmt.Errorf("stroage: invalid client input - zone id is not valid (id: %d)", zoneID), err)
		}
		conditions = append(conditions, "zone_id = ?")
		args = append(args, zoneID)
	}

	if filterName != nil {
		zoneName := *filterName
		if err := validators.ValidateName("zone", zoneName); err != nil {
			return nil, errors.Join(fmt.Errorf("invalid client input - zone name is not valid (name: %s)", zoneName), err)
		}
		zoneName = "%" + zoneName + "%"
		conditions = append(conditions, "name LIKE ?")
		args = append(args, zoneName)
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY zone_id ASC"

	limit := pageSize
	offset := (page - 1) * pageSize
	baseQuery += " LIMIT ? OFFSET ?"

	args = append(args, limit, offset)

	err := db.Select(&dbZones, baseQuery, args...)
	if err != nil {
		return nil, WrapSqliteError(fmt.Sprintf("failed to retrieve zones - operation 'retrieve-zones' encountered an issue with parameters %v", args), err)
	}

	return dbZones, nil
}
